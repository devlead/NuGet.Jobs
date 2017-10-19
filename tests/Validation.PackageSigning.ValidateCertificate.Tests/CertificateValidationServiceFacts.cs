// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using NuGet.Jobs.Validation.PackageSigning.Messages;
using NuGet.Services.Validation;
using Validation.PackageSigning.Helpers;
using Xunit;

namespace Validation.PackageSigning.ValidateCertificate.Tests
{
    public class CertificateValidationServiceFacts
    {
        public const int CertificateKey1 = 111;
        public const int CertificateKey2 = 222;

        public static readonly Guid ValidationId1 = Guid.Empty;
        public static readonly Guid ValidationId2 = new Guid("fb9c0bac-3d4d-4cc7-ac2d-b3940e15b94d");

        public class TheFindCertificateValidationAsyncMethod : FactsBase
        {
            [Fact]
            public async Task ReturnsNullIfCertificateValidationDoesntExist()
            {
                // Arrange
                _context.Mock(
                    certificateValidations: new[]
                    {
                        _certificateValidation1,
                        _certificateValidation2,
                    }
                );

                var message = new CertificateValidationMessage(
                    certificateKey: CertificateKey1,
                    validationId: ValidationId2);

                // Act & Assert
                var result = await _target.FindCertificateValidationAsync(message);

                Assert.Null(result);
            }

            [Fact]
            public async Task ReturnsCertificateValidationIfExists()
            {
                // Arrange
                _context.Mock(
                    certificateValidations: new[]
                    {
                        _certificateValidation1,
                        _certificateValidation2,
                    }
                );

                var message = new CertificateValidationMessage(
                    certificateKey: CertificateKey2,
                    validationId: ValidationId2);

                // Act & Assert
                var result = await _target.FindCertificateValidationAsync(message);

                Assert.NotNull(result);
                Assert.Equal(CertificateKey2, result.CertificateKey);
                Assert.Equal(ValidationId2, result.ValidationId);
            }
        }

        public class TheVerifyAsyncMethod : FactsBase
        {
            // TODO
        }

        public class TheTrySaveResultAsyncMethod : FactsBase
        {
            [Fact]
            public async Task GoodResultUpdatesCertificateValidation()
            {
                // Arrange
                var verificationResult = new CertificateVerificationResult(CertificateStatus.Good);

                // Act & Assert
                var result = await _target.TrySaveResultAsync(_certificateValidation1, verificationResult);

                Assert.True(result);
                Assert.Equal(CertificateStatus.Good, _certificateValidation1.Status);
                Assert.Equal(CertificateStatus.Good, _certificateValidation1.Certificate.Status);
                Assert.Equal(0, _certificateValidation1.Certificate.ValidationFailures);
                Assert.Equal(null, _certificateValidation1.Certificate.RevocationTime);
            }

            [Fact]
            public async Task InvalidResultInvalidatesDependentSignatures()
            {
                // Arrange - Invalidate a certificate that is depended on by "signature1"'s Certificate and "signature2"'s
                // trusted timestamp authority. Both "signature1" and "signature2" should be invalidated.
                var verificationResult = new CertificateVerificationResult(CertificateStatus.Invalid);

                var signingState = new PackageSigningState { SigningStatus = PackageSigningStatus.Valid };
                var signature1 = new PackageSignature { Key = 123, Status = PackageSignatureStatus.Valid };
                var signature2 = new PackageSignature { Key = 456, Status = PackageSignatureStatus.Valid };
                var signature3 = new PackageSignature { Key = 789, Status = PackageSignatureStatus.Valid };
                var timestamp = new TrustedTimestamp { Value = DateTime.UtcNow };

                signingState.PackageSignatures = new [] { signature1, signature2, signature3};
                signature1.PackageSigningState = signingState;
                signature2.PackageSigningState = signingState;
                signature3.PackageSigningState = signingState;
                signature1.Certificate = _certificate1;
                signature2.Certificate = _certificate2;
                signature3.Certificate = _certificate2;
                signature1.TrustedTimestamps = new TrustedTimestamp[0];
                signature2.TrustedTimestamps = new[] { timestamp };
                signature3.TrustedTimestamps = new TrustedTimestamp[0];
                timestamp.PackageSignature = signature2;
                timestamp.Certificate = _certificate1;
                _certificate1.PackageSignatures = new[] { signature1 };
                _certificate1.TrustedTimestamps = new[] { timestamp };

                _context.Mock(
                    packageSignatures: new[] { signature1, signature2, signature3 },
                    trustedTimestamps: new[] { timestamp });

                // Act
                var result = await _target.TrySaveResultAsync(_certificateValidation1, verificationResult);

                //  Assert - the first Unknown result shouldn't cause any issues.
                Assert.True(result);

                Assert.Equal(CertificateStatus.Invalid, _certificateValidation1.Status);

                Assert.Equal(CertificateStatus.Invalid, _certificate1.Status);
                Assert.Equal(0, _certificate1.ValidationFailures);
                Assert.Equal(null, _certificate1.RevocationTime);

                Assert.Equal(PackageSignatureStatus.Invalid, signature1.Status);
                Assert.Equal(PackageSignatureStatus.Invalid, signature2.Status);
                Assert.Equal(PackageSignatureStatus.Valid, signature3.Status);

                Assert.Equal(PackageSigningStatus.Invalid, signingState.SigningStatus);

                _alertingService.Verify(a => a.FireUnableToValidateCertificateAlert(It.IsAny<Certificate>()), Times.Never);
                _alertingService.Verify(a => a.FirePackageSignatureShouldBeInvalidatedAlert(It.IsAny<PackageSignature>()), Times.Exactly(2));
                _context.Verify(c => c.SaveChangesAsync(), Times.Once);
            }

            [Fact]
            public async Task RevokedResultInvalidatesDependentSignatures()
            {
                // Arrange - "signature1" is a signature that uses the certificate before the revocation date,
                // "signature2" is a signature that uses the certificate after the revocation date, "signature3"
                // is a signature whose trusted timestamp uses the certificate, "signature4" is a signature that
                // doesn't depend on the certificate.
                var revocationTime = DateTime.UtcNow;

                var verificationResult = new CertificateVerificationResult(revocationTime: revocationTime);

                var signingState = new PackageSigningState { SigningStatus = PackageSigningStatus.Valid };
                var signature1 = new PackageSignature { Key = 12, Status = PackageSignatureStatus.Valid };
                var signature2 = new PackageSignature { Key = 23, Status = PackageSignatureStatus.Valid };
                var signature3 = new PackageSignature { Key = 34, Status = PackageSignatureStatus.Valid };
                var signature4 = new PackageSignature { Key = 45, Status = PackageSignatureStatus.Valid };
                var timestamp1 = new TrustedTimestamp { Value = revocationTime.AddDays(-1) };
                var timestamp2 = new TrustedTimestamp { Value = revocationTime.AddDays(1) };
                var timestamp3 = new TrustedTimestamp { Value = revocationTime.AddDays(1) };
                var timestamp4 = new TrustedTimestamp { Value = revocationTime.AddDays(-1) };

                signingState.PackageSignatures = new[] { signature1, signature2, signature3, signature4 };
                signature1.PackageSigningState = signingState;
                signature2.PackageSigningState = signingState;
                signature3.PackageSigningState = signingState;
                signature4.PackageSigningState = signingState;
                signature1.Certificate = _certificate1;
                signature2.Certificate = _certificate1;
                signature3.Certificate = _certificate2;
                signature4.Certificate = _certificate2;
                signature1.TrustedTimestamps = new[] { timestamp1 }; ;
                signature2.TrustedTimestamps = new[] { timestamp2 };
                signature3.TrustedTimestamps = new[] { timestamp3 };
                signature4.TrustedTimestamps = new[] { timestamp4 };
                timestamp1.PackageSignature = signature1;
                timestamp2.PackageSignature = signature2;
                timestamp3.PackageSignature = signature3;
                timestamp4.PackageSignature = signature4;
                timestamp1.Certificate = _certificate2;
                timestamp2.Certificate = _certificate2;
                timestamp3.Certificate = _certificate1;
                timestamp4.Certificate = _certificate2;
                _certificate1.PackageSignatures = new[] { signature1, signature2 };
                _certificate2.PackageSignatures = new[] { signature3, signature4 };
                _certificate1.TrustedTimestamps = new[] { timestamp3 };
                _certificate2.TrustedTimestamps = new[] { timestamp1, timestamp2, timestamp4 };

                _context.Mock(
                    packageSigningStates: new[] { signingState },
                    packageSignatures: new[] { signature1, signature2, signature3, signature4 },
                    trustedTimestamps: new[] { timestamp1, timestamp2, timestamp3, timestamp4 },
                    certificates: new[] { _certificate1, _certificate2 });

                // Act & Assert - the first Unknown result shouldn't cause any issues.
                var result = await _target.TrySaveResultAsync(_certificateValidation1, verificationResult);

                Assert.True(result);

                Assert.Equal(CertificateStatus.Revoked, _certificateValidation1.Status);

                Assert.Equal(CertificateStatus.Revoked, _certificate1.Status);
                Assert.Equal(0, _certificate1.ValidationFailures);
                Assert.Equal(revocationTime, _certificate1.RevocationTime);

                Assert.Equal(PackageSignatureStatus.Valid, signature1.Status);
                Assert.Equal(PackageSignatureStatus.Invalid, signature2.Status);
                Assert.Equal(PackageSignatureStatus.Invalid, signature3.Status);
                Assert.Equal(PackageSignatureStatus.Valid, signature4.Status);

                Assert.Equal(PackageSigningStatus.Invalid, signingState.SigningStatus);

                _alertingService.Verify(a => a.FireUnableToValidateCertificateAlert(It.IsAny<Certificate>()), Times.Never);
                _alertingService.Verify(a => a.FirePackageSignatureShouldBeInvalidatedAlert(It.IsAny<PackageSignature>()), Times.Exactly(2));
                _context.Verify(c => c.SaveChangesAsync(), Times.Once);
            }

            [Fact]
            public async Task UnknownResultUpdatesCertificateValidation()
            {
                // Arrange - Create a signature whose certificate and trusted timestamp depends on "_certificateValidation1".
                var verificationResult = new CertificateVerificationResult(CertificateStatus.Unknown);

                var signature = new PackageSignature { Status = PackageSignatureStatus.Valid };
                var timestamp = new TrustedTimestamp { Value = DateTime.UtcNow };

                signature.Certificate = _certificate1;
                signature.TrustedTimestamps = new[] { timestamp };
                _certificate1.PackageSignatures = new[] { signature };
                _certificate1.TrustedTimestamps = new[] { timestamp };

                // Act & Assert - the first Unknown result shouldn't cause any issues.
                var result = await _target.TrySaveResultAsync(_certificateValidation1, verificationResult);

                Assert.True(result);
                Assert.Equal(null, _certificateValidation1.Status);
                Assert.Equal(CertificateStatus.Unknown, _certificateValidation1.Certificate.Status);
                Assert.Equal(4, _certificateValidation1.Certificate.ValidationFailures);
                Assert.Equal(null, _certificateValidation1.Certificate.RevocationTime);

                _alertingService.Verify(a => a.FireUnableToValidateCertificateAlert(It.IsAny<Certificate>()), Times.Never);
                _alertingService.Verify(a => a.FirePackageSignatureShouldBeInvalidatedAlert(It.IsAny<PackageSignature>()), Times.Never);
                _context.Verify(c => c.SaveChangesAsync(), Times.Once);
            }

            [Fact]
            public async Task UnknownResultAlertsIfReachesMaxFailureThreshold()
            {
                // Arrange - Create a signature whose certificate and trusted timestamp depends on "_certificateValidation1".
                var verificationResult = new CertificateVerificationResult(CertificateStatus.Unknown);

                var signature = new PackageSignature { Status = PackageSignatureStatus.Valid };
                var timestamp = new TrustedTimestamp { Value = DateTime.UtcNow };

                signature.Certificate = _certificate1;
                signature.TrustedTimestamps = new[] { timestamp };
                _certificate1.PackageSignatures = new[] { signature };
                _certificate1.TrustedTimestamps = new[] { timestamp };

                // Act & Assert - the first Unknown result shouldn't cause any issues.
                var result = await _target.TrySaveResultAsync(_certificateValidation1, verificationResult);

                Assert.True(result);
                Assert.Equal(null, _certificateValidation1.Status);
                Assert.Equal(CertificateStatus.Unknown, _certificateValidation1.Certificate.Status);
                Assert.Equal(4, _certificateValidation1.Certificate.ValidationFailures);
                Assert.Equal(null, _certificateValidation1.Certificate.RevocationTime);

                // The second result should trigger an alert but should NOT invalidate signatures.
                result = await _target.TrySaveResultAsync(_certificateValidation1, verificationResult);

                Assert.True(result);
                Assert.Equal(CertificateStatus.Invalid, _certificateValidation1.Status);
                Assert.Equal(CertificateStatus.Invalid, _certificateValidation1.Certificate.Status);
                Assert.Equal(5, _certificateValidation1.Certificate.ValidationFailures);
                Assert.Equal(null, _certificateValidation1.Certificate.RevocationTime);

                _alertingService.Verify(a => a.FireUnableToValidateCertificateAlert(It.IsAny<Certificate>()), Times.Once);
                _alertingService.Verify(a => a.FirePackageSignatureShouldBeInvalidatedAlert(It.IsAny<PackageSignature>()), Times.Never);
                _context.Verify(c => c.SaveChangesAsync(), Times.Exactly(2));
            }
        }

        public class FactsBase
        {
            protected readonly Mock<IValidationEntitiesContext> _context;
            protected readonly Mock<IAlertingService> _alertingService;

            protected readonly Certificate _certificate1 = new Certificate
            {
                Key = CertificateKey1,
                Thumbprint = "Certificate 1 Thumbprint",
                Status = CertificateStatus.Unknown,
                ValidationFailures = 3,
            };

            protected readonly Certificate _certificate2 = new Certificate
            {
                Key = CertificateKey2,
                Thumbprint = "Certificate 2 Thumbprint",
                Status = CertificateStatus.Unknown,
                ValidationFailures = 3,
            };

            protected readonly CertificateValidation _certificateValidation1 = new CertificateValidation
            {
                Key = 123,
                CertificateKey = CertificateKey1,
                ValidationId = ValidationId1,
                Status = null
            };

            protected readonly CertificateValidation _certificateValidation2 = new CertificateValidation
            {
                Key = 456,
                CertificateKey = CertificateKey2,
                ValidationId = ValidationId2,
                Status = null,
            };

            protected readonly CertificateValidationService _target;

            public FactsBase()
            {
                _context = new Mock<IValidationEntitiesContext>();
                _alertingService = new Mock<IAlertingService>();

                var logger = new Mock<ILogger<CertificateValidationService>>();

                _certificateValidation1.Certificate = _certificate1;
                _certificateValidation2.Certificate = _certificate2;

                _target = new CertificateValidationService(
                    _context.Object,
                    _alertingService.Object,
                    logger.Object,
                    maximumValidationFailures: 5);
            }
        }
    }
}
