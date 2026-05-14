from dataclasses import dataclass
import math

@dataclass
class RiskVector:
    infra: float = 0.0
    auth: float = 0.0
    secrets: float = 0.0
    ci: float = 0.0
    dataflow: float = 0.0
    tests: float = 0.0

    def score(self) -> float:
        vals = [
            self.infra,
            self.auth,
            self.secrets,
            self.ci,
            self.dataflow,
            self.tests
        ]

        vals = [max(0.0, min(v, 1.0)) for v in vals]

        # OR probabilístico independiente
        return 1 - math.prod([1 - v for v in vals])


if __name__ == "__main__":
    r = RiskVector(infra=0.8, secrets=0.6, auth=0.3)
    print("risk:", r.score())
def from_surface_context(ctx) -> RiskVector:
    return RiskVector(
        infra=getattr(ctx, "risk_multiplier", 0.0) if getattr(ctx, "surface", "") == "infra" else 0.0,
        auth=0.0,
        secrets=0.0,
        ci=0.0,
        dataflow=0.0,
        tests=0.0,
    )
def compare_models(ctx, vector: RiskVector):
    legacy = getattr(ctx, "risk_multiplier", 0.0)
    new = vector.score()

    return {
        "legacy": legacy,
        "vector": new,
        "delta": new - legacy
    }
def compare_with_legacy(ctx, vector: 'RiskVector'):
    legacy = float(getattr(ctx, "risk_multiplier", 0.0))

    vector_score = vector.score()
    vector_legacy_scale = int(min(100, max(0, vector_score * 100)))

    return {
        "legacy": legacy,
        "vector_prob": vector_score,
        "vector_scaled": vector_legacy_scale,
        "delta": vector_score - legacy
    }
