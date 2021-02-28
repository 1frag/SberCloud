create table app_users (
    id serial primary key,
    login varchar(63) not null unique,
    password varchar(127) not null,
    domain_name varchar(127) not null,
    srv_token varchar(127) not null
);

create table app_project_tokens (
    id serial primary key,
    user_id int references app_users(id) on delete cascade,
    value text not null,
    expired_at timestamp not null,
    project_id varchar(127)
);

create table app_templates (
    id serial primary key,
    raw_data json not null,
    project_id varchar(127),
    user_id int references app_users(id) on delete cascade,
    name varchar(127) not null,
    unique (name, project_id, user_id)
);
