﻿// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.Data.SqlClient;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NuGet.Services.Validation;

namespace NuGet.Jobs.Validation.PackageSigning.Storage
{
    public class ValidatorStateService : IValidatorStateService
    {
        private readonly IValidationEntitiesContext _validationContext;
        private readonly ILogger<ValidatorStateService> _logger;
        private readonly string _validatorName;

        public ValidatorStateService(
            IValidationEntitiesContext validationContext,
            Type validatorType,
            ILogger<ValidatorStateService> logger)
        {
            _validationContext = validationContext ?? throw new ArgumentNullException(nameof(validationContext));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            if (validatorType == null)
            {
                throw new ArgumentNullException(nameof(validatorType));
            }

            if (!typeof(IValidator).IsAssignableFrom(validatorType))
            {
                throw new ArgumentException($"The validator type {validatorType} must extend {nameof(IValidator)}", nameof(validatorType));
            }

            _validatorName = validatorType.Name;
        }

        public async Task<ValidatorStatus> GetStatusAsync(IValidationRequest request)
        {
            var status = await _validationContext
                                    .ValidatorStatuses
                                    .Where(s => s.ValidationId == request.ValidationId)
                                    .FirstOrDefaultAsync();

            if (status == null)
            {
                return new ValidatorStatus
                {
                    ValidationId = request.ValidationId,
                    PackageKey = request.PackageKey,
                    ValidatorName = _validatorName,
                    State = ValidationStatus.NotStarted,
                };
            }
            else if (status.PackageKey != request.PackageKey)
            {
                throw new ArgumentException(
                    $"Validation expected package key {status.PackageKey}, actual {request.PackageKey}",
                    nameof(request));
            }
            else if (status.ValidatorName != _validatorName)
            {
                throw new ArgumentException(
                    $"Validation expected validator {status.ValidatorName}, actual {_validatorName}",
                    nameof(request));
            }

            return status;
        }

        public Task<ValidatorStatus> GetStatusAsync(Guid validationId)
        {
            return _validationContext
                .ValidatorStatuses
                .Where(s => s.ValidationId == validationId)
                .FirstOrDefaultAsync();
        }

        public Task<bool> IsRevalidationRequestAsync(IValidationRequest request)
        {
            return IsRevalidationRequestAsync(request.PackageKey, request.ValidationId);
        }

        public Task<bool> IsRevalidationRequestAsync(int packageKey, Guid validationId)
        {
            return _validationContext
                        .ValidatorStatuses
                        .Where(s => s.PackageKey == packageKey)
                        .Where(s => s.ValidatorName == _validatorName)
                        .Where(s => s.ValidationId != validationId)
                        .AnyAsync();
        }

        public async Task<AddStatusResult> AddStatusAsync(ValidatorStatus status)
        {
            if (status.ValidatorName != _validatorName)
            {
                throw new ArgumentException(
                    $"Expected validator name '{_validatorName}', actual: '{status.ValidatorName}'",
                    nameof(status));
            }

            _validationContext.ValidatorStatuses.Add(status);

            try
            {
                await _validationContext.SaveChangesAsync();

                return AddStatusResult.Success;
            }
            catch (DbUpdateException e) when (e.IsUniqueConstraintViolationException())
            {
                return AddStatusResult.StatusAlreadyExists;
            }
        }

        public async Task<SaveStatusResult> SaveStatusAsync(ValidatorStatus status)
        {
            if (status.ValidatorName != _validatorName)
            {
                throw new ArgumentException(
                    $"Expected validator name '{_validatorName}', actual: '{status.ValidatorName}'",
                    nameof(status));
            }

            try
            {
                await _validationContext.SaveChangesAsync();

                return SaveStatusResult.Success;
            }
            catch (DbUpdateConcurrencyException)
            {
                return SaveStatusResult.StaleStatus;
            }
        }

        public async Task<ValidationStatus> TryAddValidatorStatusAsync(IValidationRequest request, ValidatorStatus status, ValidationStatus desiredState)
        {
            status.State = desiredState;

            var result = await AddStatusAsync(status);

            if (result == AddStatusResult.StatusAlreadyExists)
            {
                // The add operation fails if another instance of this service has already created the status.
                // This may happen due to repeated operations kicked off by the Orchestrator. Return the result from
                // the other add operation.
                _logger.LogWarning(
                    Error.ValidatorStateServiceFailedToAddStatus,
                    "Failed to add validation status for {ValidationId} ({PackageId} {PackageVersion}) as a record already exists",
                    request.PackageId,
                    request.PackageVersion);

                return (await GetStatusAsync(request)).State;
            }
            else if (result != AddStatusResult.Success)
            {
                throw new NotSupportedException($"Unknown {nameof(AddStatusResult)}: {result}");
            }

            return desiredState;
        }

        public async Task<ValidationStatus> TryUpdateValidationStatusAsync(IValidationRequest request, ValidatorStatus validatorStatus, ValidationStatus desiredState)
        {
            validatorStatus.State = desiredState;

            var result = await SaveStatusAsync(validatorStatus);

            if (result == SaveStatusResult.StaleStatus)
            {
                // The save operation fails if another instance of this service has already modified the status.
                // This may happen due to repeated operations kicked off by the Orchestrator. Return the result
                // from the other update.
                _logger.LogWarning(
                    Error.ValidatorStateServiceFailedToUpdateStatus,
                    "Failed to save validation status for {ValidationId} ({PackageId} {PackageVersion}) as the current status is stale",
                    request.PackageId,
                    request.PackageVersion);

                return (await GetStatusAsync(request)).State;
            }
            else if (result != SaveStatusResult.Success)
            {
                throw new NotSupportedException($"Unknown {nameof(SaveStatusResult)}: {result}");
            }

            return desiredState;
        }
    }
}
