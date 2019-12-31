"""Detector registry: one module per detector, looked up by name."""
from apistf.detectors.bfla import BflaDetector
from apistf.detectors.bola import BolaDetector
from apistf.detectors.business_logic import BusinessLogicDetector
from apistf.detectors.graphql import (
    GraphQLAliasAbuseDetector,
    GraphQLBatchingDetector,
    GraphQLDepthDetector,
    GraphQLIntrospectionDetector,
)
from apistf.detectors.inconsistent_authz import InconsistentAuthzDetector
from apistf.detectors.jwt import JwtDetector
from apistf.detectors.mass_assignment import ExcessiveDataDetector, MassAssignmentDetector
from apistf.detectors.rate_limit import RateLimitDetector
from apistf.detectors.session import SessionDetector

REGISTRY: dict[str, type] = {
    "bola": BolaDetector,
    "bfla": BflaDetector,
    "jwt": JwtDetector,
    "mass_assignment": MassAssignmentDetector,
    "excessive_data": ExcessiveDataDetector,
    "rate_limit": RateLimitDetector,
    "business_logic": BusinessLogicDetector,
    "inconsistent_authz": InconsistentAuthzDetector,
    "session": SessionDetector,
    "graphql_introspection": GraphQLIntrospectionDetector,
    "graphql_depth": GraphQLDepthDetector,
    "graphql_batching": GraphQLBatchingDetector,
    "graphql_alias_abuse": GraphQLAliasAbuseDetector,
}

__all__ = ["REGISTRY"]
