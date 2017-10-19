@echo OFF

cd bin

:Top
    echo "Starting job - #{Jobs.validation.Title}"

    title #{Jobs.validation.Title}

    start /w Validation.PackageSigning.ValidateCertificate.exe -Configuration #{Jobs.validation.configuration}

    echo "Finished #{Jobs.validation.Title}"

    goto Top
