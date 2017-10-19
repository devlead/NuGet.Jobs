// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using NuGet.Services.Validation;

namespace Validation.PackageSigning.ValidateCertificate
{
    public interface IAlertingService
    {
        /// <summary>
        /// Fire an alert that the signature should be manually invalidated.
        /// </summary>
        /// <param name="signature">The signature that should be invalidated.</param>
        /// <returns>A task that returns when the alert has been fired.</returns>
        void FirePackageSignatureShouldBeInvalidatedAlert(PackageSignature signature);

        /// <summary>
        /// Fire an alert that the certificate could not be validated. Manual inspection is required.
        /// </summary>
        /// <param name="certificate">The certificate that failed to be validated.</param>
        /// <returns>A task that returns when the alert has been fired.</returns>
        void FireUnableToValidateCertificateAlert(Certificate certificate);
    }
}
