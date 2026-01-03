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

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: assets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.assets (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    size bigint NOT NULL,
    mime_type character varying(100) NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    gcs_path character varying(500) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: assets_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.assets_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: assets_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.assets_id_seq OWNED BY public.assets.id;


--
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.schema_migrations (
    version character varying NOT NULL
);


--
-- Name: youtube_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.youtube_tokens (
    id integer NOT NULL,
    access_token text NOT NULL,
    refresh_token text NOT NULL,
    token_type character varying(50) NOT NULL,
    expiry timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: youtube_tokens_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.youtube_tokens_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: youtube_tokens_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.youtube_tokens_id_seq OWNED BY public.youtube_tokens.id;


--
-- Name: youtube_videos; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.youtube_videos (
    id integer NOT NULL,
    asset_id integer NOT NULL,
    youtube_id character varying(20) NOT NULL,
    title character varying(255),
    privacy_status character varying(20) DEFAULT 'private'::character varying,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: youtube_videos_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.youtube_videos_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: youtube_videos_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.youtube_videos_id_seq OWNED BY public.youtube_videos.id;


--
-- Name: assets id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assets ALTER COLUMN id SET DEFAULT nextval('public.assets_id_seq'::regclass);


--
-- Name: youtube_tokens id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.youtube_tokens ALTER COLUMN id SET DEFAULT nextval('public.youtube_tokens_id_seq'::regclass);


--
-- Name: youtube_videos id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.youtube_videos ALTER COLUMN id SET DEFAULT nextval('public.youtube_videos_id_seq'::regclass);


--
-- Name: assets assets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT assets_pkey PRIMARY KEY (id);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);


--
-- Name: youtube_tokens youtube_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.youtube_tokens
    ADD CONSTRAINT youtube_tokens_pkey PRIMARY KEY (id);


--
-- Name: youtube_videos youtube_videos_asset_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.youtube_videos
    ADD CONSTRAINT youtube_videos_asset_id_key UNIQUE (asset_id);


--
-- Name: youtube_videos youtube_videos_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.youtube_videos
    ADD CONSTRAINT youtube_videos_pkey PRIMARY KEY (id);


--
-- Name: idx_assets_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assets_created_at ON public.assets USING btree (created_at DESC);


--
-- Name: idx_assets_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assets_status ON public.assets USING btree (status);


--
-- Name: idx_youtube_videos_asset_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_youtube_videos_asset_id ON public.youtube_videos USING btree (asset_id);


--
-- Name: youtube_videos youtube_videos_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.youtube_videos
    ADD CONSTRAINT youtube_videos_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--


--
-- Dbmate schema migrations
--

INSERT INTO public.schema_migrations (version) VALUES
    ('20260102000001'),
    ('20260102000002'),
    ('20260102000003');
