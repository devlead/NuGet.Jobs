// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using NuGet.Jobs.Validation.PackageSigning.Messages;
using NuGet.Jobs.Validation.PackageSigning.Storage;
using NuGet.Services.Validation;
using Xunit;

namespace Validation.PackageSigning.ValidateCertificate.Tests
{
    public class CertificateValidationMessageHandlerFacts
    {
        public const long CertificateKey = 123;

        public static readonly Guid ValidationId = new Guid("fb9c0bac-3d4d-4cc7-ac2d-b3940e15b94d");

        public sealed class TheHandleAsyncMethod : FactsBase
        {
            [Fact]
            public async Task RetriesIfCertificateValidationDoesntExist()
            {
                // Arrange
                _certificateValidationService
                    .Setup(s => s.FindCertificateValidationAsync(It.IsAny<CertificateValidationMessage>()))
                    .Returns(Task.FromResult<CertificateValidation>(null));

                // Act & Assert
                Assert.False(await _target.HandleAsync(_message));

                _certificateValidationService.Verify(s => s.TrySaveResultAsync(It.IsAny<CertificateValidation>(), It.IsAny<CertificateVerificationResult>()), Times.Never);
            }

            [Fact]
            public async Task ConsumesMessageIfCertificateValidationEntityIsInvalid()
            {
                // Arrange
                _certificateValidationService
                    .Setup(s => s.FindCertificateValidationAsync(It.IsAny<CertificateValidationMessage>()))
                    .Returns(Task.FromResult(new CertificateValidation
                    {
                        Status = CertificateStatus.Good,
                        Certificate = new Certificate(),
                    }));

                // Act & Assert
                // The certificate validation that was found should have a null Status, but instead its Status is "Good".
                // The message handler should consume the message without performing any additional work.
                Assert.True(await _target.HandleAsync(_message));

                _certificateValidationService.Verify(s => s.TrySaveResultAsync(It.IsAny<CertificateValidation>(), It.IsAny<CertificateVerificationResult>()), Times.Never);
            }

            [Fact]
            public async Task FailsIfCertificateIsKnownToBeRevokedAndMessageDoesntHaveOverride()
            {
                // Arrange
                _certificateValidationService
                    .Setup(s => s.FindCertificateValidationAsync(It.IsAny<CertificateValidationMessage>()))
                    .Returns(Task.FromResult(new CertificateValidation
                    {
                        Status = null,
                        Certificate = new Certificate
                        {
                            Status = CertificateStatus.Revoked
                        }
                    }));

                // Act & Assert
                // The certificate is known to be revoked, the handler should block validation as the message does not have the
                // "RevalidateRevokedCertificate" override set.
                Assert.True(await _target.HandleAsync(_message));

                _certificateValidationService.Verify(s => s.TrySaveResultAsync(It.IsAny<CertificateValidation>(), It.IsAny<CertificateVerificationResult>()), Times.Never);
            }

            [Fact]
            public async Task RetriesIfSavingCertificateValidationEntityFails()
            {
                // Arrange
                _certificateValidationService
                    .Setup(s => s.FindCertificateValidationAsync(It.IsAny<CertificateValidationMessage>()))
                    .Returns(Task.FromResult(new CertificateValidation
                    {
                        Status = null,
                        Certificate = new Certificate
                        {
                            Status = CertificateStatus.Unknown
                        }
                    }));

                _certificateValidationService
                    .Setup(s => s.TrySaveResultAsync(It.IsAny<CertificateValidation>(), It.IsAny<CertificateVerificationResult>()))
                    .Returns(Task.FromResult(false));

                // Act & Assert
                // Saving the result failed, the handler should retry.
                Assert.False(await _target.HandleAsync(_message));
            }

            public static IEnumerable<object[]> MessageIsConsumedIfValidationEndsGracefullyData()
            {
                yield return new[] { new CertificateVerificationResult(CertificateStatus.Good) };

                yield return new[] { new CertificateVerificationResult(CertificateStatus.Invalid) };

                yield return new[] { new CertificateVerificationResult(revocationTime: DateTime.UtcNow) };
            }

            [Theory]
            [MemberData(nameof(MessageIsConsumedIfValidationEndsGracefullyData))]
            public async Task MessageIsConsumedIfValidationEndsGracefully(CertificateVerificationResult result)
            {
                // Arrange
                _certificateValidationService
                    .Setup(s => s.FindCertificateValidationAsync(It.IsAny<CertificateValidationMessage>()))
                    .Returns(Task.FromResult(new CertificateValidation
                    {
                        Status = null,
                        Certificate = new Certificate
                        {
                            Status = CertificateStatus.Unknown
                        }
                    }));

                _certificateValidationService
                    .Setup(s => s.VerifyAsync(It.IsAny<X509Certificate2>()))
                    .Returns(Task.FromResult(result));

                _certificateValidationService
                    .Setup(s => s.TrySaveResultAsync(It.IsAny<CertificateValidation>(), It.IsAny<CertificateVerificationResult>()))
                    .Returns(Task.FromResult(true));

                // Act & Assert
                Assert.True(await _target.HandleAsync(_message));

                _certificateValidationService
                    .Verify(s => s.TrySaveResultAsync(It.IsAny<CertificateValidation>(), It.IsAny<CertificateVerificationResult>()), Times.Once);
            }

            [Fact]
            public async Task RetriesIfValidationFailureIsBelowThreshold()
            {
                // Arrange & Act & Assert
                // The maximum validation failures is set to 5. A certificate whose verification result is "Unknown" with 3
                // pre-existing validation failures should be retried.
                Assert.False(await HandleUnknownResultAsync(validationFailuresStart: 3));
            }

            [Fact]
            public async Task MessageIsConsumedIfValidationFailureCountReachesThreshold()
            {
                // Arrange & Act & Assert
                // The maximum validation failures is set to 5. A certificate whose verification result is "Unknown" with 4
                // pre-existing validation failures should NOT be retried.
                Assert.True(await HandleUnknownResultAsync(validationFailuresStart: 4));
            }

            private async Task<bool> HandleUnknownResultAsync(int validationFailuresStart)
            {
                // Arrange
                // Return an "Unknown" status for the certificate's verification. The validation service should increment the number
                // of failures for the validation's certificate.
                var certificateValidation = new CertificateValidation
                {
                    Status = null,
                    Certificate = new Certificate
                    {
                        Status = CertificateStatus.Unknown,
                        ValidationFailures = validationFailuresStart
                    }
                };

                _certificateValidationService
                    .Setup(s => s.FindCertificateValidationAsync(It.IsAny<CertificateValidationMessage>()))
                    .Returns(Task.FromResult(certificateValidation));

                _certificateValidationService
                    .Setup(s => s.VerifyAsync(It.IsAny<X509Certificate2>()))
                    .Returns(Task.FromResult(new CertificateVerificationResult(CertificateStatus.Unknown)));

                _certificateValidationService
                    .Setup(
                        s => s.TrySaveResultAsync(
                                It.IsAny<CertificateValidation>(),
                                It.Is<CertificateVerificationResult>(r => r.Status == CertificateStatus.Unknown)))
                    .Callback<CertificateValidation, CertificateVerificationResult>((v, r) => v.Certificate.ValidationFailures++)
                    .Returns(Task.FromResult(true));

                // Act & Assert
                var result = await _target.HandleAsync(_message);

                Assert.Equal(validationFailuresStart + 1, certificateValidation.Certificate.ValidationFailures);

                _certificateValidationService
                    .Verify(s => s.TrySaveResultAsync(It.IsAny<CertificateValidation>(), It.IsAny<CertificateVerificationResult>()), Times.Once);

                return result;
            }
        }

        public class FactsBase
        {
            protected readonly Mock<ICertificateStore> _certificateStore;
            protected readonly Mock<ICertificateValidationService> _certificateValidationService;

            protected readonly CertificateValidationMessage _message;

            protected readonly CertificateValidationMessageHandler _target;

            public FactsBase(int maximumValidationFailures = 5)
            {
                _certificateStore = new Mock<ICertificateStore>();
                _certificateValidationService = new Mock<ICertificateValidationService>();

                _message = new CertificateValidationMessage(CertificateKey, ValidationId, revalidateRevokedCertificate: false);

                var logger = new Mock<ILogger<CertificateValidationMessageHandler>>();

                _target = new CertificateValidationMessageHandler(
                    _certificateStore.Object,
                    _certificateValidationService.Object,
                    logger.Object,
                    maximumValidationFailures);
            }

        }
    }
}
