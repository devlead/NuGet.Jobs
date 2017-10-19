// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using NuGet.Services.Validation;

namespace Validation.PackageSigning.ValidateCertificate
{
    public class AlertingService : IAlertingService
    {
        public void FirePackageSignatureShouldBeInvalidatedAlert(PackageSignature signature)
        {
            // TODO
            throw new NotImplementedException();
        }

        public void FireUnableToValidateCertificateAlert(Certificate certificate)
        {
            // TODO
            throw new NotImplementedException();
        }
    }
}
