-- A table created and then dropped must not be reported: it does not exist.
create table temp_import_staging (
  id bigserial primary key,
  payload jsonb
);

drop table temp_import_staging;
