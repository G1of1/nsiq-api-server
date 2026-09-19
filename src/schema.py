from pydantic import BaseModel, Field

class HostRequest(BaseModel):
    host: str


class DomainRequest(BaseModel):
    domain: str = Field(min_length=1, max_length=253)


class AssessmentRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    authorized: bool
    ports: list[int] = Field(default_factory=lambda: [80, 443, 22, 21, 25, 3389], max_length=20)
