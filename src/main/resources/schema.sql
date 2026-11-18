create table if not exists graph_snapshot (
    id bigint auto_increment primary key,
    kind varchar(16) not null,
    service varchar(255),
    revision varchar(65535),
    created_at timestamp not null,
    content clob not null
);

-- A system snapshot's revision lists every service's (a@r1,b@r2,..), longer than the 255 earlier databases allow.
-- Widening only changes the column's metadata, so running it again is free.
alter table graph_snapshot alter column revision set data type varchar(65535);

create index if not exists graph_snapshot_service on graph_snapshot (kind, service, id);
