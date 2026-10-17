"""Non-circular bootstrap authority and adoption support."""

from .authority import (
    AuthorityVerificationError,
    BootstrapAuthorityVerifier,
    ExternalVerificationRequest,
    VerifiedAuthority,
    VerifiedOperation,
    VerifiedToolRelease,
)
from .registry import (
    authority_profile_digest,
    BootstrapAttemptRegistry,
    BootstrapRegistryCrash,
    BootstrapRegistryError,
    input_manifest_digest,
    output_profile_digest,
)
from .legacy_claim import (
    CanonicalClaimPublisher,
    LegacyClaimCoordinator,
    LegacyClaimCrash,
    LegacyClaimError,
    LegacyPrepareAdapter,
    SignedReceiptIssuer,
    handoff_response,
)
from .adoption_prepare import (
    AdoptionPrepareCoordinator,
    AdoptionPrepareCrash,
    AdoptionPrepareError,
    AdoptionRepositoryInspector,
    AdoptionSecretProvider,
)
from .adoption_publish import (
    AdoptionPublishCoordinator,
    AdoptionPublishCrash,
    AdoptionPublishError,
    AdoptionRepositoryController,
    adoption_activation_response,
)
from .foundation_payload import (
    FoundationPayloadError,
    build_claim_adoption_request,
    build_foundation_payload_manifest,
    verify_prepared_package,
    write_prepared_package,
)
from .foundation_verification import (
    AdoptionFoundationVerificationStore,
    FoundationVerificationCrash,
    FoundationVerificationError,
)
from .repository_handoff import (
    RepositoryHandoffCrash,
    RepositoryHandoffError,
    RepositoryHandoffStore,
)
from .git_adoption import GitAdoptionError, GitAdoptionRepository
from .authority_driver import (
    BootstrapAuthorityDriver,
    BootstrapAuthorityDriverError,
    BootstrapAuthorityDriverRejection,
    VerifiedDriverInvocation,
)
from .git_claim import GitCanonicalClaimPublisher, GitClaimPublisherError
from .crypto_verifier import (
    CryptographicVerificationError,
    ExternalPublicKey,
    OpenSslEd25519ExternalVerifier,
)
from .operation_handlers import BootstrapOperationHandlerError, UpstreamBootstrapOperationHandlers

__all__ = [
    "AuthorityVerificationError",
    "BootstrapAuthorityVerifier",
    "ExternalVerificationRequest",
    "VerifiedAuthority",
    "VerifiedOperation",
    "VerifiedToolRelease",
    "BootstrapAttemptRegistry",
    "BootstrapRegistryCrash",
    "BootstrapRegistryError",
    "authority_profile_digest",
    "input_manifest_digest",
    "output_profile_digest",
    "CanonicalClaimPublisher",
    "LegacyClaimCoordinator",
    "LegacyClaimCrash",
    "LegacyClaimError",
    "LegacyPrepareAdapter",
    "SignedReceiptIssuer",
    "handoff_response",
    "AdoptionPrepareCoordinator",
    "AdoptionPrepareCrash",
    "AdoptionPrepareError",
    "AdoptionRepositoryInspector",
    "AdoptionSecretProvider",
    "AdoptionPublishCoordinator",
    "AdoptionPublishCrash",
    "AdoptionPublishError",
    "AdoptionRepositoryController",
    "adoption_activation_response",
    "FoundationPayloadError",
    "build_claim_adoption_request",
    "build_foundation_payload_manifest",
    "verify_prepared_package",
    "write_prepared_package",
    "AdoptionFoundationVerificationStore",
    "FoundationVerificationCrash",
    "FoundationVerificationError",
    "RepositoryHandoffCrash",
    "RepositoryHandoffError",
    "RepositoryHandoffStore",
    "GitAdoptionError",
    "GitAdoptionRepository",
    "BootstrapAuthorityDriver",
    "BootstrapAuthorityDriverError",
    "BootstrapAuthorityDriverRejection",
    "VerifiedDriverInvocation",
    "GitCanonicalClaimPublisher",
    "GitClaimPublisherError",
    "CryptographicVerificationError",
    "ExternalPublicKey",
    "OpenSslEd25519ExternalVerifier",
    "BootstrapOperationHandlerError",
    "UpstreamBootstrapOperationHandlers",
]
