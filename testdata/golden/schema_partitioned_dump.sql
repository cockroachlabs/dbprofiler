--
-- PostgreSQL database dump
--

\restrict kyLdR8Hrv1iWLToTgmj1Kf2cGXQPFKvIF88lQl5lGTVbS2zkhwKO6hadWzouUx8

-- Dumped from database version 16.15 (Debian 16.15-1.pgdg13+2)
-- Dumped by pg_dump version 16.15 (Debian 16.15-1.pgdg13+2)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: sales; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA sales;


SET default_tablespace = '';

--
-- Name: accounts; Type: TABLE; Schema: sales; Owner: -
--

CREATE TABLE sales.accounts (
    id bigint NOT NULL,
    tier text NOT NULL,
    opened_on date
)
PARTITION BY LIST (tier);


SET default_table_access_method = heap;

--
-- Name: accounts_premium; Type: TABLE; Schema: sales; Owner: -
--

CREATE TABLE sales.accounts_premium (
    id bigint NOT NULL,
    tier text NOT NULL,
    opened_on date
);


--
-- Name: accounts_standard; Type: TABLE; Schema: sales; Owner: -
--

CREATE TABLE sales.accounts_standard (
    id bigint NOT NULL,
    tier text NOT NULL,
    opened_on date
);


--
-- Name: events; Type: TABLE; Schema: sales; Owner: -
--

CREATE TABLE sales.events (
    id bigint NOT NULL,
    occurred_at timestamp with time zone NOT NULL,
    kind text NOT NULL
)
PARTITION BY RANGE (occurred_at);


--
-- Name: events_2026; Type: TABLE; Schema: sales; Owner: -
--

CREATE TABLE sales.events_2026 (
    id bigint NOT NULL,
    occurred_at timestamp with time zone NOT NULL,
    kind text NOT NULL
)
PARTITION BY LIST (kind);


--
-- Name: events_2026_click; Type: TABLE; Schema: sales; Owner: -
--

CREATE TABLE sales.events_2026_click (
    id bigint NOT NULL,
    occurred_at timestamp with time zone NOT NULL,
    kind text NOT NULL
);


--
-- Name: events_2026_view; Type: TABLE; Schema: sales; Owner: -
--

CREATE TABLE sales.events_2026_view (
    id bigint NOT NULL,
    occurred_at timestamp with time zone NOT NULL,
    kind text NOT NULL
);


--
-- Name: regions; Type: TABLE; Schema: sales; Owner: -
--

CREATE TABLE sales.regions (
    id integer NOT NULL,
    name text NOT NULL
);


--
-- Name: shipments; Type: TABLE; Schema: sales; Owner: -
--

CREATE TABLE sales.shipments (
    id bigint NOT NULL,
    region_id integer NOT NULL,
    shipped_at timestamp with time zone NOT NULL,
    carrier text
)
PARTITION BY RANGE (shipped_at);


--
-- Name: shipments_2025; Type: TABLE; Schema: sales; Owner: -
--

CREATE TABLE sales.shipments_2025 (
    id bigint NOT NULL,
    region_id integer NOT NULL,
    shipped_at timestamp with time zone NOT NULL,
    carrier text
);


--
-- Name: shipments_2026; Type: TABLE; Schema: sales; Owner: -
--

CREATE TABLE sales.shipments_2026 (
    id bigint NOT NULL,
    region_id integer NOT NULL,
    shipped_at timestamp with time zone NOT NULL,
    carrier text
);


--
-- Name: shipments_overflow; Type: TABLE; Schema: sales; Owner: -
--

CREATE TABLE sales.shipments_overflow (
    id bigint NOT NULL,
    region_id integer NOT NULL,
    shipped_at timestamp with time zone NOT NULL,
    carrier text
);


--
-- Name: accounts_premium; Type: TABLE ATTACH; Schema: sales; Owner: -
--

ALTER TABLE ONLY sales.accounts ATTACH PARTITION sales.accounts_premium FOR VALUES IN ('premium');


--
-- Name: accounts_standard; Type: TABLE ATTACH; Schema: sales; Owner: -
--

ALTER TABLE ONLY sales.accounts ATTACH PARTITION sales.accounts_standard FOR VALUES IN ('standard');


--
-- Name: events_2026; Type: TABLE ATTACH; Schema: sales; Owner: -
--

ALTER TABLE ONLY sales.events ATTACH PARTITION sales.events_2026 FOR VALUES FROM ('2026-01-01 00:00:00+00') TO ('2027-01-01 00:00:00+00');


--
-- Name: events_2026_click; Type: TABLE ATTACH; Schema: sales; Owner: -
--

ALTER TABLE ONLY sales.events_2026 ATTACH PARTITION sales.events_2026_click FOR VALUES IN ('click');


--
-- Name: events_2026_view; Type: TABLE ATTACH; Schema: sales; Owner: -
--

ALTER TABLE ONLY sales.events_2026 ATTACH PARTITION sales.events_2026_view FOR VALUES IN ('view');


--
-- Name: shipments_2025; Type: TABLE ATTACH; Schema: sales; Owner: -
--

ALTER TABLE ONLY sales.shipments ATTACH PARTITION sales.shipments_2025 FOR VALUES FROM ('2025-01-01 00:00:00+00') TO ('2026-01-01 00:00:00+00');


--
-- Name: shipments_2026; Type: TABLE ATTACH; Schema: sales; Owner: -
--

ALTER TABLE ONLY sales.shipments ATTACH PARTITION sales.shipments_2026 FOR VALUES FROM ('2026-01-01 00:00:00+00') TO ('2027-01-01 00:00:00+00');


--
-- Name: shipments_overflow; Type: TABLE ATTACH; Schema: sales; Owner: -
--

ALTER TABLE ONLY sales.shipments ATTACH PARTITION sales.shipments_overflow DEFAULT;


--
-- Name: accounts accounts_pkey; Type: CONSTRAINT; Schema: sales; Owner: -
--

ALTER TABLE ONLY sales.accounts
    ADD CONSTRAINT accounts_pkey PRIMARY KEY (id, tier);


--
-- Name: accounts_premium accounts_premium_pkey; Type: CONSTRAINT; Schema: sales; Owner: -
--

ALTER TABLE ONLY sales.accounts_premium
    ADD CONSTRAINT accounts_premium_pkey PRIMARY KEY (id, tier);


--
-- Name: accounts_standard accounts_standard_pkey; Type: CONSTRAINT; Schema: sales; Owner: -
--

ALTER TABLE ONLY sales.accounts_standard
    ADD CONSTRAINT accounts_standard_pkey PRIMARY KEY (id, tier);


--
-- Name: events events_pkey; Type: CONSTRAINT; Schema: sales; Owner: -
--

ALTER TABLE ONLY sales.events
    ADD CONSTRAINT events_pkey PRIMARY KEY (id, occurred_at, kind);


--
-- Name: events_2026 events_2026_pkey; Type: CONSTRAINT; Schema: sales; Owner: -
--

ALTER TABLE ONLY sales.events_2026
    ADD CONSTRAINT events_2026_pkey PRIMARY KEY (id, occurred_at, kind);


--
-- Name: events_2026_click events_2026_click_pkey; Type: CONSTRAINT; Schema: sales; Owner: -
--

ALTER TABLE ONLY sales.events_2026_click
    ADD CONSTRAINT events_2026_click_pkey PRIMARY KEY (id, occurred_at, kind);


--
-- Name: events_2026_view events_2026_view_pkey; Type: CONSTRAINT; Schema: sales; Owner: -
--

ALTER TABLE ONLY sales.events_2026_view
    ADD CONSTRAINT events_2026_view_pkey PRIMARY KEY (id, occurred_at, kind);


--
-- Name: regions regions_pkey; Type: CONSTRAINT; Schema: sales; Owner: -
--

ALTER TABLE ONLY sales.regions
    ADD CONSTRAINT regions_pkey PRIMARY KEY (id);


--
-- Name: shipments shipments_pkey; Type: CONSTRAINT; Schema: sales; Owner: -
--

ALTER TABLE ONLY sales.shipments
    ADD CONSTRAINT shipments_pkey PRIMARY KEY (id, shipped_at);


--
-- Name: shipments_2025 shipments_2025_pkey; Type: CONSTRAINT; Schema: sales; Owner: -
--

ALTER TABLE ONLY sales.shipments_2025
    ADD CONSTRAINT shipments_2025_pkey PRIMARY KEY (id, shipped_at);


--
-- Name: shipments_2026 shipments_2026_pkey; Type: CONSTRAINT; Schema: sales; Owner: -
--

ALTER TABLE ONLY sales.shipments_2026
    ADD CONSTRAINT shipments_2026_pkey PRIMARY KEY (id, shipped_at);


--
-- Name: shipments_overflow shipments_overflow_pkey; Type: CONSTRAINT; Schema: sales; Owner: -
--

ALTER TABLE ONLY sales.shipments_overflow
    ADD CONSTRAINT shipments_overflow_pkey PRIMARY KEY (id, shipped_at);


--
-- Name: shipments_carrier_idx; Type: INDEX; Schema: sales; Owner: -
--

CREATE INDEX shipments_carrier_idx ON ONLY sales.shipments USING btree (carrier);


--
-- Name: shipments_2025_carrier_idx; Type: INDEX; Schema: sales; Owner: -
--

CREATE INDEX shipments_2025_carrier_idx ON sales.shipments_2025 USING btree (carrier);


--
-- Name: shipments_2026_carrier_idx; Type: INDEX; Schema: sales; Owner: -
--

CREATE INDEX shipments_2026_carrier_idx ON sales.shipments_2026 USING btree (carrier);


--
-- Name: shipments_overflow_carrier_idx; Type: INDEX; Schema: sales; Owner: -
--

CREATE INDEX shipments_overflow_carrier_idx ON sales.shipments_overflow USING btree (carrier);


--
-- Name: accounts_premium_pkey; Type: INDEX ATTACH; Schema: sales; Owner: -
--

ALTER INDEX sales.accounts_pkey ATTACH PARTITION sales.accounts_premium_pkey;


--
-- Name: accounts_standard_pkey; Type: INDEX ATTACH; Schema: sales; Owner: -
--

ALTER INDEX sales.accounts_pkey ATTACH PARTITION sales.accounts_standard_pkey;


--
-- Name: events_2026_click_pkey; Type: INDEX ATTACH; Schema: sales; Owner: -
--

ALTER INDEX sales.events_2026_pkey ATTACH PARTITION sales.events_2026_click_pkey;


--
-- Name: events_2026_pkey; Type: INDEX ATTACH; Schema: sales; Owner: -
--

ALTER INDEX sales.events_pkey ATTACH PARTITION sales.events_2026_pkey;


--
-- Name: events_2026_view_pkey; Type: INDEX ATTACH; Schema: sales; Owner: -
--

ALTER INDEX sales.events_2026_pkey ATTACH PARTITION sales.events_2026_view_pkey;


--
-- Name: shipments_2025_carrier_idx; Type: INDEX ATTACH; Schema: sales; Owner: -
--

ALTER INDEX sales.shipments_carrier_idx ATTACH PARTITION sales.shipments_2025_carrier_idx;


--
-- Name: shipments_2025_pkey; Type: INDEX ATTACH; Schema: sales; Owner: -
--

ALTER INDEX sales.shipments_pkey ATTACH PARTITION sales.shipments_2025_pkey;


--
-- Name: shipments_2026_carrier_idx; Type: INDEX ATTACH; Schema: sales; Owner: -
--

ALTER INDEX sales.shipments_carrier_idx ATTACH PARTITION sales.shipments_2026_carrier_idx;


--
-- Name: shipments_2026_pkey; Type: INDEX ATTACH; Schema: sales; Owner: -
--

ALTER INDEX sales.shipments_pkey ATTACH PARTITION sales.shipments_2026_pkey;


--
-- Name: shipments_overflow_carrier_idx; Type: INDEX ATTACH; Schema: sales; Owner: -
--

ALTER INDEX sales.shipments_carrier_idx ATTACH PARTITION sales.shipments_overflow_carrier_idx;


--
-- Name: shipments_overflow_pkey; Type: INDEX ATTACH; Schema: sales; Owner: -
--

ALTER INDEX sales.shipments_pkey ATTACH PARTITION sales.shipments_overflow_pkey;


--
-- Name: shipments shipments_region_id_fkey; Type: FK CONSTRAINT; Schema: sales; Owner: -
--

ALTER TABLE sales.shipments
    ADD CONSTRAINT shipments_region_id_fkey FOREIGN KEY (region_id) REFERENCES sales.regions(id);


--
-- PostgreSQL database dump complete
--

\unrestrict kyLdR8Hrv1iWLToTgmj1Kf2cGXQPFKvIF88lQl5lGTVbS2zkhwKO6hadWzouUx8

