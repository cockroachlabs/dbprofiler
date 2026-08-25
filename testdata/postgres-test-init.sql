-- Runs once, on first start of an empty volume, against POSTGRES_DB as
-- POSTGRES_USER. See docker-compose.postgres-test.yml and docs/TESTING.md.
--
-- pg_stat_statements is preloaded by the server command line but still has to
-- be created in the database that will be profiled. Without it the integration
-- test would exercise the degraded path -- which has its own unit coverage --
-- instead of the one that reads the view.
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
