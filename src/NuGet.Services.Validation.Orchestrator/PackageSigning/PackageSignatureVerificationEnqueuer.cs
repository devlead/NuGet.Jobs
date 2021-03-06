﻿// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Threading.Tasks;
using NuGet.Jobs.Validation.PackageSigning.Messages;
using NuGet.Services.ServiceBus;

namespace NuGet.Services.Validation.PackageSigning
{
    /// <summary>
    /// Kicks off package signature verifications.
    /// </summary>
    public class PackageSignatureVerificationEnqueuer : IPackageSignatureVerificationEnqueuer
    {
        private readonly ITopicClient _topicClient;
        private readonly IBrokeredMessageSerializer<SignatureValidationMessage> _signatureValidationSerializer;

        public PackageSignatureVerificationEnqueuer(
            ITopicClient topicClient,
            IBrokeredMessageSerializer<SignatureValidationMessage> signatureValidationSerializer)
        {
            _topicClient = topicClient ?? throw new ArgumentNullException(nameof(topicClient));
            _signatureValidationSerializer = signatureValidationSerializer ?? throw new ArgumentNullException(nameof(signatureValidationSerializer));
        }

        /// <summary>
        /// Kicks off the package verification process for the given request. Verification will begin when the
        /// <see cref="ValidationEntitiesContext"/> has a <see cref="ValidatorStatus"/> that matches the
        /// <see cref="IValidationRequest"/>'s validationId. Once verification completes, the <see cref="ValidatorStatus"/>'s
        /// State will be updated to "Succeeded" or "Failed".
        /// </summary>
        /// <param name="request">The request that details the package to be verified.</param>
        /// <returns>A task that will complete when the verification process has been queued.</returns>
        public Task EnqueueVerificationAsync(IValidationRequest request)
        {
            var brokeredMessage = _signatureValidationSerializer.Serialize(
                new SignatureValidationMessage(request.PackageId, request.PackageVersion, new Uri(request.NupkgUrl), request.ValidationId));

            return _topicClient.SendAsync(brokeredMessage);
        }
    }
}
