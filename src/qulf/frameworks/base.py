from pydantic import BaseModel

QULF_COOKIE_NAME = "qulf_session"


class SignInRequest(BaseModel):
    email: str
    password: str
