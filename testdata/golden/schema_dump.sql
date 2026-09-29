--
-- PostgreSQL database dump
--

-- Dumped from database version 16.2 (Debian 16.2-1.pgdg120+2)
-- Dumped by pg_dump version 16.2

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


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: audit_ddl(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.audit_ddl() RETURNS event_trigger
    LANGUAGE plpgsql
    AS $$ BEGIN RAISE NOTICE 'ddl'; END; $$;


--
-- Name: touch_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.touch_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$ BEGIN NEW.updated_at := now(); RETURN NEW; END; $$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: orders; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.orders (
    id bigint NOT NULL,
    placed_by bigint NOT NULL,
    region_code text NOT NULL,
    total numeric(12,2) NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE orders; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.orders IS 'One row per placed order.';


--
-- Name: COLUMN orders.total; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.orders.total IS 'Order total in the reporting currency.';


--
-- Name: regions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.regions (
    code text NOT NULL,
    label text NOT NULL
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id bigint NOT NULL,
    email text NOT NULL,
    manager_id bigint
);


--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.users_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: invoices; Type: TABLE; Schema: sales; Owner: -
--

CREATE TABLE sales.invoices (
    id bigint NOT NULL,
    order_id bigint NOT NULL,
    issued_on date NOT NULL
);


--
-- Name: recent_orders; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.recent_orders AS
 SELECT id,
    placed_by,
    total
   FROM public.orders
  WHERE (updated_at > (now() - '30 days'::interval));


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Name: orders orders_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_pkey PRIMARY KEY (id);


--
-- Name: orders orders_total_check; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_total_check CHECK ((total >= (0)::numeric)) NOT VALID;


--
-- Name: regions regions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.regions
    ADD CONSTRAINT regions_pkey PRIMARY KEY (code);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: invoices invoices_pkey; Type: CONSTRAINT; Schema: sales; Owner: -
--

ALTER TABLE ONLY sales.invoices
    ADD CONSTRAINT invoices_pkey PRIMARY KEY (id);


--
-- Name: orders_placed_by_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX orders_placed_by_idx ON public.orders USING btree (placed_by);


--
-- Name: orders_region_code_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX orders_region_code_idx ON public.orders USING btree (region_code);


--
-- Name: invoices_order_id_idx; Type: INDEX; Schema: sales; Owner: -
--

CREATE INDEX invoices_order_id_idx ON sales.invoices USING btree (order_id);


--
-- Name: invoices_replica_identity_idx; Type: INDEX; Schema: sales; Owner: -
--

CREATE UNIQUE INDEX invoices_replica_identity_idx ON sales.invoices USING btree (id, issued_on);

ALTER TABLE ONLY sales.invoices REPLICA IDENTITY USING INDEX invoices_replica_identity_idx;


--
-- Name: orders touch_orders; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER touch_orders BEFORE UPDATE ON public.orders FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();


--
-- Name: orders orders_placed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_placed_by_fkey FOREIGN KEY (placed_by) REFERENCES public.users(id);


--
-- Name: orders orders_region_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_region_code_fkey FOREIGN KEY (region_code) REFERENCES public.regions(code);


--
-- Name: users users_manager_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_manager_id_fkey FOREIGN KEY (manager_id) REFERENCES public.users(id);


--
-- Name: invoices invoices_order_id_fkey; Type: FK CONSTRAINT; Schema: sales; Owner: -
--

ALTER TABLE ONLY sales.invoices
    ADD CONSTRAINT invoices_order_id_fkey FOREIGN KEY (order_id) REFERENCES public.orders(id);


--
-- Name: ledger_pub; Type: PUBLICATION; Schema: -; Owner: -
--

CREATE PUBLICATION ledger_pub WITH (publish = 'insert, update, delete, truncate');


--
-- Name: ledger_pub orders; Type: PUBLICATION TABLE; Schema: public; Owner: -
--

ALTER PUBLICATION ledger_pub ADD TABLE ONLY public.orders;


--
-- Name: audit_ddl; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER audit_ddl ON ddl_command_end
   EXECUTE FUNCTION public.audit_ddl();


--
-- PostgreSQL database dump complete
--

