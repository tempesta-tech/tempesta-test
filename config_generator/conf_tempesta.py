from pydantic import BaseModel, validator
from typing import List, Optional


class ListenSocket(BaseModel):
    address: str
    port: str
    proto: Optional[str]

    @validator('proto')
    def name_must_contain_space(cls, proto_value):
        if proto_value:
            return 'proto={0}'.format(proto_value)


class ServerGroup(BaseModel):
    name: str
    address: str
    port: str


class VHost(BaseModel):
    name: str
    proxy_pass: str


class TempestaConf(BaseModel):

    listen_sockets: List[ListenSocket]
    server_groups: Optional[List[ServerGroup]]
    vhosts: Optional[List[VHost]]
    tls_cert: Optional[str]
    tls_key: Optional[str]
    cache: int = 0
    http_chain: Optional[List[str]]
