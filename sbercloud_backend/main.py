import aiohttp
import aiohttp_validate
import aiopg.sa
import hashlib
import os
import logging
import json
import time
import datetime

from aiohttp import web
from dotenv import load_dotenv
from pathlib import Path
from typing import Optional, Literal
from pprint import pprint as print  # noqa
from dateutil.parser import parse as date_parse

env_path = Path(__file__).parent.parent / 'prod.env'
load_dotenv(dotenv_path=env_path)
logging.basicConfig(level="DEBUG")

TOKEN_URL = "https://iam.ru-moscow-1.hc.sbercloud.ru/v3/auth/tokens"
PROJECT_URL = "https://iam.ru-moscow-1.hc.sbercloud.ru/v3/projects"
EYE_METRIC_LIST_URL = "https://ces.ru-moscow-1.hc.sbercloud.ru/V1.0/{project_id}/metrics"
EYE_METRIC_DATA_URL = "https://ces.ru-moscow-1.hc.sbercloud.ru/V1.0/{project_id}/metric-data"
TRACE_URL = "https://cts.ru-moscow-1.hc.sbercloud.ru/v1.0/{project_id}/system/trace"
CCE_CLUSTERS_URL = "https://cce.ru-moscow-1.hc.sbercloud.ru/api/v3/projects/{project_id}/clusters"
AOM_METRIC_LIST_URL = "https://apm.ru-moscow-1.hc.sbercloud.ru/v1/{project_id}/ams/metrics"
AOM_METRIC_DATA_URL = "https://apm.ru-moscow-1.hc.sbercloud.ru/v1/{project_id}/ams/metricdata"
VERBOSE_NAMESPACE = {
    "SYS.ECS": "Elastic Cloud Server",
    "AGT.ECS": "Elastic Cloud Server",
    "SYS.AS": "Auto Scaling",
    "SYS.EVS": "Elastic Volume Service",
    "SYS.OBS": "Object Storage Service",
    "SYS.SFS": "Scalable File Service",
    "SYS.VPC": "Elastic IP and bandwidth",
    "SYS.ELB": "Elastic Load Balance",
    "SYS.NAT": "NAT Gateway",
    "SYS.DMS": "Distributed Message Service",
    "SYS.DCS": "Distributed Cache Service",
    "SYS.RDS": "Relational Database Service",
    "SYS.DDS": "Document Database Service",
    "SYS.ES": "Cloud Search Service",
}
BODY_LOGIN = """{
    "auth": {
        "identity": {
            "methods": ["password"],
            "password": {
                "user": {
                    "name": "{{ LOGIN }}",
                    "password": "{{ PASSWORD }}",
                    "domain": {
                        "name": "{{ DOMAIN_NAME }}"
                    }
                }
            }
        },
        "scope": {
            "{{ SCOPE_LABEL }}": {
                "{{ SCOPE_TARGET }}": "{{ SCOPE }}"
            }
        }
    }
}"""
BODY_APM = """{
    "metricItems": [
        {
            "namespace": "PAAS.SLA",
            "dimensions":[
                {
                    "name":"clusterName",
                    "value":"{{ NAME }}"
                }
            ]
        }
    ]
}"""
BODY_OAM_METRIC_QUERY = """{
    "metrics": [
        {
            "namespace": "{{ NAMESPACE }}",
            "metricName": "{{ METRIC_NAME }}",
            "dimensions": [
                {
                    "name": "clusterName",
                    "value": "{{ CLUSTER_NAME }}"
                }
            ]
        }
    ],
    "period": 60,
    "timerange": "-1.-1.5",
    "statistics": ["average"]
}"""


def verbose_namespace(key):
    return VERBOSE_NAMESPACE.get(key, key.split(".")[1])


class Application(web.Application):
    class Request(web.Request):
        app: 'Application'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.db: Optional[aiopg.sa.engine.Engine] = None
        self.cleanup_ctx.append(self.database)

    async def database(self, *_):
        """Setup database for application"""
        config = {'dsn': os.getenv('DATABASE_URL')}
        self.db = await aiopg.sa.create_engine(**config)
        yield
        self.db.close()
        await self.db.wait_closed()


async def get_cloud_token_by_srv_token(conn: aiopg.sa.connection.SAConnection, srv_token: str):
    row = await conn.execute("""
        select pt.value from app_project_tokens pt
        inner join app_users u on u.id = pt.user_id
        where (U.srv_token = %s) and (pt.project_id is null) and \
            (pt.expired_at > (now() - interval '5 minutes'))
    """, (srv_token,))
    row = await row.fetchone()
    return None if row is None else row["value"]


async def get_token_by_credentials(
        login: str,
        password: str,
        domain_name: str,
        project_id: str = '',
        *,
        scope: Literal["project", "domain"] = "project"
) -> tuple[[tuple[Optional[str], Optional[datetime.datetime]]], Optional[str]]:
    body = (BODY_LOGIN
            .replace("{{ LOGIN }}", login)
            .replace("{{ PASSWORD }}", password)
            .replace("{{ DOMAIN_NAME }}", domain_name)
            .replace("{{ SCOPE }}", project_id if scope == "project" else domain_name)
            .replace("{{ SCOPE_LABEL }}", scope)
            .replace("{{ SCOPE_TARGET }}", "id" if scope == "project" else "name"))

    print(body)
    async with aiohttp.ClientSession() as session:
        async with session.post(TOKEN_URL, data=body) as resp:
            if "X-Subject-Token" not in resp.headers:
                logging.info(f"invalid credentials ({login = }, {password = }, "
                             f"{domain_name = }, {project_id = }, {scope = })")
                return (None, None), 'Invalid credentials. Check logs'  # Нам дали левые credentials

            cloud_token: str = resp.headers["X-Subject-Token"]
            expires_at: datetime.datetime = date_parse((await resp.json())["token"]["expires_at"])
            return (cloud_token, expires_at), None


async def user_by_srv_token(conn: aiopg.sa.connection.SAConnection, srv_token: str):
    row = await conn.execute("""
        select id, login, password, domain_name from app_users u
        where U.srv_token = %s
    """, (srv_token,))
    return await row.fetchone()


async def get_alive_project_token(
        conn: aiopg.sa.connection.SAConnection,
        srv_token: str,
        project_id: str
):
    row = await conn.execute("""
            select pt.value from app_project_tokens pt
            inner join app_users u on u.id = pt.user_id
            where (U.srv_token = %s) and (pt.project_id = %s) and \
                (pt.expired_at > (now() - interval '5 minutes'))
        """, (srv_token, project_id))
    if row := await row.fetchone():  # Token is already in DB. Just return it.
        return row["value"]


async def insert_new_token(
        conn: aiopg.sa.connection.SAConnection,
        user_id: int, value: str, expired_at: datetime.datetime,
        project_id: Optional[str],
):
    return await conn.execute("""
        insert into app_project_tokens (user_id, value, expired_at, project_id)
        values (%s, %s, %s, %s)
    """, (user_id, value, expired_at, project_id))


async def get_or_create_cloud_project_token_by_srv_token(
        conn: aiopg.sa.connection.SAConnection, srv_token: str, project_id: str
) -> Optional[str]:
    if token := await get_alive_project_token(conn, srv_token, project_id):
        return token

    row = await user_by_srv_token(conn, srv_token)
    (cloud_project_token, expired_at), err = await get_token_by_credentials(
        row["login"], row["password"], row["domain_name"], project_id
    )
    if isinstance(err, str):
        return None

    await insert_new_token(conn, row["id"], cloud_project_token, expired_at, project_id)
    return cloud_project_token


async def get_alive_domain_token(
        conn: aiopg.sa.connection.SAConnection, srv_token: str,
):
    row = await conn.execute("""
            select pt.value from app_project_tokens pt
            inner join app_users u on u.id = pt.user_id
            where (U.srv_token = %s) and (pt.expired_at > now() - interval '5 minutes') and \
                (pt.project_id is null)
        """, (srv_token,))
    row = await row.fetchone()
    return row["value"] if row else None


async def get_or_update_cloud_domain_token_by_srv_token(
        conn: aiopg.sa.connection.SAConnection, srv_token: str
) -> Optional[str]:
    if token := await get_alive_domain_token(conn, srv_token):
        return token

    if not (user := await user_by_srv_token(conn, srv_token)):
        return

    (cloud_token, expired_at), err = await get_token_by_credentials(
        user["login"], user["password"], user["domain_name"], scope="domain"
    )
    await insert_new_token(conn, user["id"], cloud_token, expired_at, None)
    return cloud_token


async def auth(request: 'Application.Request', project_id: Optional[str]):
    if not (srv_token := fetch_token(request)):
        logging.info("AUTHORIZATION header is missed")
        raise web.HTTPUnauthorized() from None

    async with request.app.db.acquire() as conn:
        if project_id:
            print("get_or_create_cloud_project_token_by_srv_token")
            cloud_token = await get_or_create_cloud_project_token_by_srv_token(conn, srv_token, project_id)
        else:
            print("get_or_update_cloud_domain_token_by_srv_token")
            cloud_token = await get_or_update_cloud_domain_token_by_srv_token(conn, srv_token)

    if not cloud_token:
        raise web.HTTPUnauthorized() from None
    return cloud_token


async def projects_handler(request: 'Application.Request'):
    cloud_token = await auth(request, None)
    print(cloud_token)

    headers = {"X-Auth-Token": cloud_token}

    async with aiohttp.ClientSession() as session:
        async with session.get(PROJECT_URL, headers=headers) as resp:
            resp = await resp.json()

    def inner():
        for proj in resp["projects"][1:]:
            yield {
                "name": proj["name"],
                "id": proj["id"],
                "description": proj["description"]
            }

    return web.json_response({
        "response": list(inner()),
        "status": 200,
    })


def uniques(iterable):
    seen, result = set(), []
    for elem in iterable:
        if tuple(elem.items()) not in seen:
            result.append(elem)
            seen.add(tuple(elem.items()))
    return result


async def get_metric_list(project_id: str, cloud_token: str, *, mn2dim_target=False):
    mn2dim = dict()
    url = EYE_METRIC_LIST_URL.format(project_id=project_id)
    headers = {"X-Auth-Token": cloud_token}

    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers) as resp:
            if resp.status != 200:  # todo: Понять почему 403
                logging.error(f"{await resp.json() = } {resp.status = } {headers = }")
                raise web.HTTPServerError()
            resp = await resp.json()

    def inner():
        for metric in resp["metrics"]:
            yield {
                "id": metric["namespace"],
                "metric_name": metric["metric_name"],
                "name": verbose_namespace(metric["namespace"]),
            }

    if mn2dim_target:
        for metric in resp["metrics"]:
            mn2dim[metric["metric_name"]] = ','.join(
                [metric["dimensions"][0]["name"], metric["dimensions"][0]["value"]]
            )  # todo: ignore kafka with 2 dimensions?

        return mn2dim

    return {"metrics": uniques(inner())}


async def metric_name_to_dim(metric_name: str, project_id: str, cloud_token: str):
    data = await get_metric_list(project_id, cloud_token, mn2dim_target=True)
    print(data.get(metric_name))
    try:
        return data[metric_name]
    except KeyError:
        raise web.HTTPNotFound() from None


@aiohttp_validate.validate(
    request_schema={
        "type": "object",
        "properties": {
            "login": {"type": "string"},
            "password": {"type": "string"},
            "domain_name": {"type": "string"},
        },
        "required": ["login", "password"],
        "additionalProperties": False
    }
)
async def login_handler(form: dict, request: 'Application.Request'):
    if "domain_name" not in form:
        # It is user from android where application isn't supporting non-admin login =(
        logging.warning("Deprecated method is used")  # let's annoy in logs =)
        form["domain_name"] = form["login"]

    srv_token = hashlib.md5(  # Токен нашего backend
        (form["login"] + os.getenv("SALT", "SALT_SRV") + form["password"]).encode()
    ).hexdigest()

    (cloud_token, expired_at), err = await get_token_by_credentials(  # Токен SberCloud
        form["login"], form["password"], form["domain_name"], scope="domain",
    )
    if isinstance(err, str):
        return web.HTTPUnauthorized(body=err)

    async with request.app.db.acquire() as conn:  # type: aiopg.sa.SAConnection
        user_id = await conn.execute(r"""
            INSERT INTO app_users (login, password, domain_name, srv_token)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (login) DO NOTHING
            RETURNING id;
        """, (form["login"], form["password"], form["domain_name"], srv_token))

        if user_id := await user_id.fetchone():  # пользователь впервые
            await conn.execute(r"""
                INSERT INTO app_project_tokens (user_id, value, expired_at, project_id)
                VALUES (%s, %s, %s, %s);
            """, (user_id["id"], cloud_token, expired_at, None))

    return web.json_response({"srv_token": srv_token, "status": 200})


@aiohttp_validate.validate(
    request_schema={
        "type": "object",
        "properties": {
            "project_id": {"type": "string"},
        },
        "additionalProperties": False
    }
)
async def eye_metric_list_handler(form: dict, request: 'Application.Request'):
    cloud_token = await auth(request, form["project_id"])
    data = await get_metric_list(form["project_id"], cloud_token)
    return web.json_response(data)


def best_period(numb):
    return ([*filter(lambda x: numb // x > 10, (86400, 14400, 3600, 1200, 300, 1))] + [1])[0]


@aiohttp_validate.validate(
    request_schema={
        "type": "object",
        "properties": {
            "project_id": {"type": "string"},
            "duration_sec": {"type": "integer"},
            "namespace": {"type": "string"},
            "metric_name": {"type": "string"},
        },
        "required": ["project_id", "namespace", "metric_name"],
        "additionalProperties": False
    }
)
async def eye_query_handler(form: dict, request: 'Application.Request'):
    form.setdefault("duration_sec", 5 * 60)
    cloud_token = await auth(request, form["project_id"])
    headers = {"X-Auth-Token": cloud_token}
    url = EYE_METRIC_DATA_URL.format(project_id=form["project_id"])

    async with aiohttp.ClientSession() as session:
        print(url)
        async with session.get(url, headers=headers, params=(params := {
            "namespace": form["namespace"],
            "metric_name": form["metric_name"],
            "from": 1000 * int(time.time() - form["duration_sec"]),
            "to": 1000 * int(time.time()),
            "period": best_period(form["duration_sec"]),
            "filter": "average",  # todo: только avg?
            "dim.0": await metric_name_to_dim(form["metric_name"], form["project_id"], cloud_token),
        })) as resp:
            print(params)
            return web.json_response(await resp.json())


@aiohttp_validate.validate(
    request_schema={
        "type": "object",
        "properties": {
            "project_id": {"type": "string"},
            "duration_sec": {"type": "integer"},
        },
        "required": ["project_id", "duration_sec"],
        "additionalProperties": False
    }
)
async def cts_handler(form: dict, request: 'Application.Request'):
    # trace_status trace_id user.name record_time
    cloud_token = await auth(request, form["project_id"])
    headers = {"X-Auth-Token": cloud_token}
    url = TRACE_URL.format(project_id=form["project_id"])

    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, params={
            "from": 1000 * int(time.time() - form["duration_sec"]),
            "to": 1000 * int(time.time()),
        }) as resp:
            resp = await resp.json()

    def inner():
        for trace in resp["traces"]:
            print(trace)
            detail = trace.get("response", {})
            yield {
                "Id": trace["trace_id"],
                "Trace Name": trace["trace_name"],
                "Resource Type": trace["resource_type"],
                "Trace Status": trace["trace_status"],
                "Operator": trace["user"]["name"],
                "Operation Time": trace["record_time"],
                "Details": detail.get("details", {}).get("details") if isinstance(detail, dict) else None,
            }

    return web.json_response(list(inner()))


@aiohttp_validate.validate(
    request_schema={
        "type": "object",
        "properties": {
            "project_id": {"type": "string"},
            "duration_sec": {"type": "integer"},
            "trace_id": {"type": "string"},
        },
        "required": ["project_id", "duration_sec"],
        "additionalProperties": False
    }
)
async def cts_detail_handler(form: dict, request: 'Application.Request'):
    cloud_token = await auth(request, form["project_id"])
    headers = {"X-Auth-Token": cloud_token}
    url = TRACE_URL.format(project_id=form["project_id"])

    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, params={
            "from": 1000 * int(time.time() - form["duration_sec"]),
            "to": 1000 * int(time.time()),
        }) as resp:
            for trace in (await resp.json())["traces"]:
                if trace["trace_id"] == form["trace_id"]:
                    return web.json_response(trace)

    return web.HTTPNotFound()


@aiohttp_validate.validate(
    request_schema={
        "type": "object",
        "properties": {
            "project_id": {"type": "string"},
        },
        "required": ["project_id"],
        "additionalProperties": False
    }
)
async def clusters_overview_handler(form: dict, request: 'Application.Request'):
    cloud_token = await auth(request, form["project_id"])
    headers = {"X-Auth-Token": cloud_token, "Content-Type": "application/json"}
    url = CCE_CLUSTERS_URL.format(project_id=form["project_id"])

    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers) as resp:
            print((resp.status, await resp.text()))
            resp = await resp.json()

    def inner():
        for item in resp["items"]:
            yield {
                "uid": item["metadata"]["uid"],
                "name": item["metadata"]["name"],
                "update_at": date_parse(item["metadata"]["updateTimestamp"][:26]).timestamp(),
                "status": item["status"]["phase"],
                "flavor": item["spec"]["flavor"],
            }

    return web.json_response({"clusters": list(inner())})


@aiohttp_validate.validate(
    request_schema={
        "type": "object",
        "properties": {
            "project_id": {"type": "string"},
            "cluster_name": {"type": "string"},
        },
        "required": ["project_id", "cluster_name"],
        "additionalProperties": False
    }
)
async def aom_metric_list_handler(form: dict, request: 'Application.Request'):
    cloud_token = await auth(request, form["project_id"])
    headers = {"X-Auth-Token": cloud_token, "Content-Type": "application/json"}
    url = AOM_METRIC_LIST_URL.format(project_id=form["project_id"])
    body = (BODY_APM
            .replace("{{ NAME }}", form["cluster_name"]))

    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, data=body) as resp:
            resp = await resp.json()

    def inner():
        for metric in resp["metrics"]:
            yield {
                "namespace": metric["namespace"],
                "metricName": metric["metricName"],
                "unit": metric["unit"],
            }

    return web.json_response({"metrics": list(inner())})


@aiohttp_validate.validate(
    request_schema={
        "type": "object",
        "properties": {
            "project_id": {"type": "string"},
            "namespace": {"type": "string"},
            "metric_name": {"type": "string"},
            "cluster_name": {"type": "string"},  # +todo: specify timerange format
        },
        "required": ["project_id", "namespace", "metric_name", "cluster_name"],
        "additionalProperties": False
    }
)
async def aom_query_handler(form: dict, request: 'Application.Request'):
    form.setdefault("duration_sec", 5 * 60)
    cloud_token = await auth(request, form["project_id"])
    headers = {"X-Auth-Token": cloud_token, "Content-Type": "application/json"}
    url = AOM_METRIC_DATA_URL.format(project_id=form["project_id"])
    body = (BODY_OAM_METRIC_QUERY
            .replace("{{ METRIC_NAME }}", form["metric_name"])
            .replace("{{ CLUSTER_NAME }}", form["cluster_name"])
            .replace("{{ NAMESPACE }}", form["namespace"]))

    async with aiohttp.ClientSession() as session:
        print(url)
        async with session.post(url, headers=headers, data=body) as resp:
            resp = await resp.json()

    def inner():
        for point in resp["metrics"][0]["dataPoints"]:
            yield {
                "timestamp": point["timestamp"],
                "unit": point["unit"],
                "average": point["statistics"][0]["value"],
            }

    return web.json_response({"points": list(inner())})


def fetch_token(request: 'Application.Request') -> str:
    return request.headers.get("AUTHORIZATION", "").removeprefix("Bearer ")


async def inner_auth(conn: aiopg.sa.connection.SAConnection, request: 'Application.Request'):
    if not (user := await user_by_srv_token(conn, fetch_token(request))):
        raise web.HTTPUnauthorized() from None
    return user


@aiohttp_validate.validate(
    request_schema={
        "type": "object",
        "properties": {
            "project_id": {"type": "string"},
            "name": {"type": "string"},
            "raw_data": {"type": "object"},
        },
        "required": ["project_id", "name", "raw_data"],
        "additionalProperties": False
    }
)
async def templates_post_handler(form: dict, request: 'Application.Request'):
    async with request.app.db.acquire() as conn:  # type: aiopg.sa.SAConnection
        user = await inner_auth(conn, request)

        raw_data = json.dumps(form["raw_data"])
        template = await conn.execute(r"""
            INSERT INTO app_templates (raw_data, project_id, user_id, name)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT DO NOTHING
            RETURNING id;
        """, (raw_data, form["project_id"], user["id"], form["name"]))
        template = await template.fetchone()
        if template is None:
            return web.json_response({"template_id": None, "status": 400, "reason": "name conflict"})

    return web.json_response({"template_id": template["id"], "status": 201})


async def templates_get_handler(request: 'Application.Request'):
    if not (project_id := request.query.get("project_id")):
        return web.json_response({"reason": "project_id isn't specified"}, status=400)

    async with request.app.db.acquire() as conn:  # type: aiopg.sa.SAConnection
        user = await inner_auth(conn, request)

        data = await conn.execute(r"""
            SELECT T.id, T.raw_data, T.user_id, T.name FROM app_templates T
            WHERE (T.project_id = %s) and (T.user_id = %s)
        """, (project_id, user["id"]))
        data = await data.fetchall()

    return web.json_response({
        "templates": list(map(lambda x: dict(x.items()), data)),
    })


async def templates_delete_handler(request: 'Application.Request'):
    if not (project_id := request.query.get("project_id")):
        return web.json_response({"reason": "project_id isn't specified"}, status=400)
    if not (template_id := request.query.get("template_id")):
        return web.json_response({"reason": "template_id isn't specified"}, status=400)

    async with request.app.db.acquire() as conn:  # type: aiopg.sa.SAConnection
        user = await inner_auth(conn, request)

        data = await conn.execute(r"""
            DELETE FROM app_templates T
            WHERE (T.project_id = %s) and (T.user_id = %s) and (T.id = %s)
            RETURNING T.id
        """, (project_id, user["id"], template_id))
        data = await data.fetchall()

    if len(data) > 1:
        logging.error(f"{data = }. query delete few template once")
        return web.HTTPServerError()
    elif len(data) == 1:
        return web.HTTPNoContent()
    else:
        return web.HTTPNotFound()


def main():
    app = Application()
    app.add_routes([
        web.route('POST', '/v1/login', login_handler),
        web.route('POST', '/v1/projects', projects_handler),

        web.route('POST', '/v1/eye/metric_list', eye_metric_list_handler),
        web.route('POST', '/v1/eye/query', eye_query_handler),

        web.route('POST', '/v1/cts/overview', cts_handler),
        web.route('POST', '/v1/cts/detail', cts_detail_handler),

        web.route('POST', '/v1/cce/clusters/overview', clusters_overview_handler),
        web.route('POST', '/v1/aom/metric_list', aom_metric_list_handler),
        web.route('POST', '/v1/aom/query', aom_query_handler),

        web.route('GET', '/v1/templates', templates_get_handler),
        web.route('POST', '/v1/templates', templates_post_handler),
        web.route('DELETE', '/v1/templates', templates_delete_handler),

        web.static('/spec', Path(__file__).parent / 'static'),
    ])
    web.run_app(app)


if __name__ == '__main__':
    main()
