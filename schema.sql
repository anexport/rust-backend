--
-- PostgreSQL database dump
--

\restrict RexxHFwxBHHUwpGswBcpsq6whlfPgMjqrRoGFRJaarjXjqAvQ3hfzHGxMnwAfwa

-- Dumped from database version 17.6
-- Dumped by pg_dump version 17.8 (Homebrew)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: auth; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA auth;


--
-- Name: pg_cron; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_cron WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION pg_cron; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pg_cron IS 'Job scheduler for PostgreSQL';


--
-- Name: extensions; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA extensions;


--
-- Name: graphql; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA graphql;


--
-- Name: graphql_public; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA graphql_public;


--
-- Name: pg_net; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_net WITH SCHEMA extensions;


--
-- Name: EXTENSION pg_net; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pg_net IS 'Async HTTP';


--
-- Name: pgbouncer; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA pgbouncer;


--
-- Name: realtime; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA realtime;


--
-- Name: storage; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA storage;


--
-- Name: supabase_migrations; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA supabase_migrations;


--
-- Name: vault; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA vault;


--
-- Name: hypopg; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS hypopg WITH SCHEMA extensions;


--
-- Name: EXTENSION hypopg; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION hypopg IS 'Hypothetical indexes for PostgreSQL';


--
-- Name: index_advisor; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS index_advisor WITH SCHEMA extensions;


--
-- Name: EXTENSION index_advisor; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION index_advisor IS 'Query index advisor';


--
-- Name: pg_graphql; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_graphql WITH SCHEMA graphql;


--
-- Name: EXTENSION pg_graphql; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pg_graphql IS 'pg_graphql: GraphQL support';


--
-- Name: pg_stat_statements; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_stat_statements WITH SCHEMA extensions;


--
-- Name: EXTENSION pg_stat_statements; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pg_stat_statements IS 'track planning and execution statistics of all SQL statements executed';


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: postgis; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS postgis WITH SCHEMA public;


--
-- Name: EXTENSION postgis; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION postgis IS 'PostGIS geometry and geography spatial types and functions';


--
-- Name: supabase_vault; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS supabase_vault WITH SCHEMA vault;


--
-- Name: EXTENSION supabase_vault; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION supabase_vault IS 'Supabase Vault Extension';


--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA extensions;


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


--
-- Name: aal_level; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.aal_level AS ENUM (
    'aal1',
    'aal2',
    'aal3'
);


--
-- Name: code_challenge_method; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.code_challenge_method AS ENUM (
    's256',
    'plain'
);


--
-- Name: factor_status; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.factor_status AS ENUM (
    'unverified',
    'verified'
);


--
-- Name: factor_type; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.factor_type AS ENUM (
    'totp',
    'webauthn',
    'phone'
);


--
-- Name: oauth_authorization_status; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.oauth_authorization_status AS ENUM (
    'pending',
    'approved',
    'denied',
    'expired'
);


--
-- Name: oauth_client_type; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.oauth_client_type AS ENUM (
    'public',
    'confidential'
);


--
-- Name: oauth_registration_type; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.oauth_registration_type AS ENUM (
    'dynamic',
    'manual'
);


--
-- Name: oauth_response_type; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.oauth_response_type AS ENUM (
    'code'
);


--
-- Name: one_time_token_type; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.one_time_token_type AS ENUM (
    'confirmation_token',
    'reauthentication_token',
    'recovery_token',
    'email_change_token_new',
    'email_change_token_current',
    'phone_change_token'
);


--
-- Name: booking_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.booking_status AS ENUM (
    'pending',
    'paid',
    'awaiting_pickup_inspection',
    'awaiting_start_date',
    'approved',
    'active',
    'awaiting_return_inspection',
    'pending_owner_review',
    'declined',
    'cancelled',
    'completed',
    'disputed'
);


--
-- Name: claim_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.claim_status AS ENUM (
    'pending',
    'accepted',
    'disputed',
    'resolved',
    'escalated'
);


--
-- Name: deposit_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.deposit_status AS ENUM (
    'held',
    'releasing',
    'released',
    'claimed',
    'refunded'
);


--
-- Name: TYPE deposit_status; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TYPE public.deposit_status IS 'Deposit status lifecycle: held → releasing (transient lock) → released/claimed/refunded';


--
-- Name: equipment_condition; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.equipment_condition AS ENUM (
    'new',
    'excellent',
    'good',
    'fair'
);


--
-- Name: inspection_type; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.inspection_type AS ENUM (
    'pickup',
    'return'
);


--
-- Name: notification_priority; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.notification_priority AS ENUM (
    'low',
    'medium',
    'high',
    'critical'
);


--
-- Name: notification_type; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.notification_type AS ENUM (
    'booking_confirmed',
    'booking_cancelled',
    'booking_completed',
    'booking_reminder',
    'new_message',
    'payment_received',
    'payment_processed',
    'payout_sent',
    'refund_issued',
    'review_received',
    'verification_approved',
    'verification_rejected',
    'verification_reminder',
    'equipment_favorited',
    'equipment_views_milestone',
    'system_announcement',
    'promotion',
    'verification_submitted'
);


--
-- Name: user_role; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.user_role AS ENUM (
    'renter',
    'owner',
    'admin'
);


--
-- Name: verification_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.verification_status AS ENUM (
    'unverified',
    'pending',
    'verified',
    'rejected'
);


--
-- Name: TYPE verification_status; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TYPE public.verification_status IS 'Status of a user verification: unverified, pending, verified, or rejected';


--
-- Name: action; Type: TYPE; Schema: realtime; Owner: -
--

CREATE TYPE realtime.action AS ENUM (
    'INSERT',
    'UPDATE',
    'DELETE',
    'TRUNCATE',
    'ERROR'
);


--
-- Name: equality_op; Type: TYPE; Schema: realtime; Owner: -
--

CREATE TYPE realtime.equality_op AS ENUM (
    'eq',
    'neq',
    'lt',
    'lte',
    'gt',
    'gte',
    'in'
);


--
-- Name: user_defined_filter; Type: TYPE; Schema: realtime; Owner: -
--

CREATE TYPE realtime.user_defined_filter AS (
	column_name text,
	op realtime.equality_op,
	value text
);


--
-- Name: wal_column; Type: TYPE; Schema: realtime; Owner: -
--

CREATE TYPE realtime.wal_column AS (
	name text,
	type_name text,
	type_oid oid,
	value jsonb,
	is_pkey boolean,
	is_selectable boolean
);


--
-- Name: wal_rls; Type: TYPE; Schema: realtime; Owner: -
--

CREATE TYPE realtime.wal_rls AS (
	wal jsonb,
	is_rls_enabled boolean,
	subscription_ids uuid[],
	errors text[]
);


--
-- Name: buckettype; Type: TYPE; Schema: storage; Owner: -
--

CREATE TYPE storage.buckettype AS ENUM (
    'STANDARD',
    'ANALYTICS',
    'VECTOR'
);


--
-- Name: email(); Type: FUNCTION; Schema: auth; Owner: -
--

CREATE FUNCTION auth.email() RETURNS text
    LANGUAGE sql STABLE
    AS $$
  select 
  coalesce(
    nullif(current_setting('request.jwt.claim.email', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'email')
  )::text
$$;


--
-- Name: FUNCTION email(); Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON FUNCTION auth.email() IS 'Deprecated. Use auth.jwt() -> ''email'' instead.';


--
-- Name: jwt(); Type: FUNCTION; Schema: auth; Owner: -
--

CREATE FUNCTION auth.jwt() RETURNS jsonb
    LANGUAGE sql STABLE
    AS $$
  select 
    coalesce(
        nullif(current_setting('request.jwt.claim', true), ''),
        nullif(current_setting('request.jwt.claims', true), '')
    )::jsonb
$$;


--
-- Name: role(); Type: FUNCTION; Schema: auth; Owner: -
--

CREATE FUNCTION auth.role() RETURNS text
    LANGUAGE sql STABLE
    AS $$
  select 
  coalesce(
    nullif(current_setting('request.jwt.claim.role', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role')
  )::text
$$;


--
-- Name: FUNCTION role(); Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON FUNCTION auth.role() IS 'Deprecated. Use auth.jwt() -> ''role'' instead.';


--
-- Name: uid(); Type: FUNCTION; Schema: auth; Owner: -
--

CREATE FUNCTION auth.uid() RETURNS uuid
    LANGUAGE sql STABLE
    AS $$
  select 
  coalesce(
    nullif(current_setting('request.jwt.claim.sub', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
  )::uuid
$$;


--
-- Name: FUNCTION uid(); Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON FUNCTION auth.uid() IS 'Deprecated. Use auth.jwt() -> ''sub'' instead.';


--
-- Name: grant_pg_cron_access(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION extensions.grant_pg_cron_access() RETURNS event_trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF EXISTS (
    SELECT
    FROM pg_event_trigger_ddl_commands() AS ev
    JOIN pg_extension AS ext
    ON ev.objid = ext.oid
    WHERE ext.extname = 'pg_cron'
  )
  THEN
    grant usage on schema cron to postgres with grant option;

    alter default privileges in schema cron grant all on tables to postgres with grant option;
    alter default privileges in schema cron grant all on functions to postgres with grant option;
    alter default privileges in schema cron grant all on sequences to postgres with grant option;

    alter default privileges for user supabase_admin in schema cron grant all
        on sequences to postgres with grant option;
    alter default privileges for user supabase_admin in schema cron grant all
        on tables to postgres with grant option;
    alter default privileges for user supabase_admin in schema cron grant all
        on functions to postgres with grant option;

    grant all privileges on all tables in schema cron to postgres with grant option;
    revoke all on table cron.job from postgres;
    grant select on table cron.job to postgres with grant option;
  END IF;
END;
$$;


--
-- Name: FUNCTION grant_pg_cron_access(); Type: COMMENT; Schema: extensions; Owner: -
--

COMMENT ON FUNCTION extensions.grant_pg_cron_access() IS 'Grants access to pg_cron';


--
-- Name: grant_pg_graphql_access(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION extensions.grant_pg_graphql_access() RETURNS event_trigger
    LANGUAGE plpgsql
    AS $_$
DECLARE
    func_is_graphql_resolve bool;
BEGIN
    func_is_graphql_resolve = (
        SELECT n.proname = 'resolve'
        FROM pg_event_trigger_ddl_commands() AS ev
        LEFT JOIN pg_catalog.pg_proc AS n
        ON ev.objid = n.oid
    );

    IF func_is_graphql_resolve
    THEN
        -- Update public wrapper to pass all arguments through to the pg_graphql resolve func
        DROP FUNCTION IF EXISTS graphql_public.graphql;
        create or replace function graphql_public.graphql(
            "operationName" text default null,
            query text default null,
            variables jsonb default null,
            extensions jsonb default null
        )
            returns jsonb
            language sql
        as $$
            select graphql.resolve(
                query := query,
                variables := coalesce(variables, '{}'),
                "operationName" := "operationName",
                extensions := extensions
            );
        $$;

        -- This hook executes when `graphql.resolve` is created. That is not necessarily the last
        -- function in the extension so we need to grant permissions on existing entities AND
        -- update default permissions to any others that are created after `graphql.resolve`
        grant usage on schema graphql to postgres, anon, authenticated, service_role;
        grant select on all tables in schema graphql to postgres, anon, authenticated, service_role;
        grant execute on all functions in schema graphql to postgres, anon, authenticated, service_role;
        grant all on all sequences in schema graphql to postgres, anon, authenticated, service_role;
        alter default privileges in schema graphql grant all on tables to postgres, anon, authenticated, service_role;
        alter default privileges in schema graphql grant all on functions to postgres, anon, authenticated, service_role;
        alter default privileges in schema graphql grant all on sequences to postgres, anon, authenticated, service_role;

        -- Allow postgres role to allow granting usage on graphql and graphql_public schemas to custom roles
        grant usage on schema graphql_public to postgres with grant option;
        grant usage on schema graphql to postgres with grant option;
    END IF;

END;
$_$;


--
-- Name: FUNCTION grant_pg_graphql_access(); Type: COMMENT; Schema: extensions; Owner: -
--

COMMENT ON FUNCTION extensions.grant_pg_graphql_access() IS 'Grants access to pg_graphql';


--
-- Name: grant_pg_net_access(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION extensions.grant_pg_net_access() RETURNS event_trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_event_trigger_ddl_commands() AS ev
    JOIN pg_extension AS ext
    ON ev.objid = ext.oid
    WHERE ext.extname = 'pg_net'
  )
  THEN
    IF NOT EXISTS (
      SELECT 1
      FROM pg_roles
      WHERE rolname = 'supabase_functions_admin'
    )
    THEN
      CREATE USER supabase_functions_admin NOINHERIT CREATEROLE LOGIN NOREPLICATION;
    END IF;

    GRANT USAGE ON SCHEMA net TO supabase_functions_admin, postgres, anon, authenticated, service_role;

    IF EXISTS (
      SELECT FROM pg_extension
      WHERE extname = 'pg_net'
      -- all versions in use on existing projects as of 2025-02-20
      -- version 0.12.0 onwards don't need these applied
      AND extversion IN ('0.2', '0.6', '0.7', '0.7.1', '0.8', '0.10.0', '0.11.0')
    ) THEN
      ALTER function net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) SECURITY DEFINER;
      ALTER function net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) SECURITY DEFINER;

      ALTER function net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) SET search_path = net;
      ALTER function net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) SET search_path = net;

      REVOKE ALL ON FUNCTION net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) FROM PUBLIC;
      REVOKE ALL ON FUNCTION net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) FROM PUBLIC;

      GRANT EXECUTE ON FUNCTION net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) TO supabase_functions_admin, postgres, anon, authenticated, service_role;
      GRANT EXECUTE ON FUNCTION net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) TO supabase_functions_admin, postgres, anon, authenticated, service_role;
    END IF;
  END IF;
END;
$$;


--
-- Name: FUNCTION grant_pg_net_access(); Type: COMMENT; Schema: extensions; Owner: -
--

COMMENT ON FUNCTION extensions.grant_pg_net_access() IS 'Grants access to pg_net';


--
-- Name: pgrst_ddl_watch(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION extensions.pgrst_ddl_watch() RETURNS event_trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  cmd record;
BEGIN
  FOR cmd IN SELECT * FROM pg_event_trigger_ddl_commands()
  LOOP
    IF cmd.command_tag IN (
      'CREATE SCHEMA', 'ALTER SCHEMA'
    , 'CREATE TABLE', 'CREATE TABLE AS', 'SELECT INTO', 'ALTER TABLE'
    , 'CREATE FOREIGN TABLE', 'ALTER FOREIGN TABLE'
    , 'CREATE VIEW', 'ALTER VIEW'
    , 'CREATE MATERIALIZED VIEW', 'ALTER MATERIALIZED VIEW'
    , 'CREATE FUNCTION', 'ALTER FUNCTION'
    , 'CREATE TRIGGER'
    , 'CREATE TYPE', 'ALTER TYPE'
    , 'CREATE RULE'
    , 'COMMENT'
    )
    -- don't notify in case of CREATE TEMP table or other objects created on pg_temp
    AND cmd.schema_name is distinct from 'pg_temp'
    THEN
      NOTIFY pgrst, 'reload schema';
    END IF;
  END LOOP;
END; $$;


--
-- Name: pgrst_drop_watch(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION extensions.pgrst_drop_watch() RETURNS event_trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  obj record;
BEGIN
  FOR obj IN SELECT * FROM pg_event_trigger_dropped_objects()
  LOOP
    IF obj.object_type IN (
      'schema'
    , 'table'
    , 'foreign table'
    , 'view'
    , 'materialized view'
    , 'function'
    , 'trigger'
    , 'type'
    , 'rule'
    )
    AND obj.is_temporary IS false -- no pg_temp objects
    THEN
      NOTIFY pgrst, 'reload schema';
    END IF;
  END LOOP;
END; $$;


--
-- Name: set_graphql_placeholder(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION extensions.set_graphql_placeholder() RETURNS event_trigger
    LANGUAGE plpgsql
    AS $_$
    DECLARE
    graphql_is_dropped bool;
    BEGIN
    graphql_is_dropped = (
        SELECT ev.schema_name = 'graphql_public'
        FROM pg_event_trigger_dropped_objects() AS ev
        WHERE ev.schema_name = 'graphql_public'
    );

    IF graphql_is_dropped
    THEN
        create or replace function graphql_public.graphql(
            "operationName" text default null,
            query text default null,
            variables jsonb default null,
            extensions jsonb default null
        )
            returns jsonb
            language plpgsql
        as $$
            DECLARE
                server_version float;
            BEGIN
                server_version = (SELECT (SPLIT_PART((select version()), ' ', 2))::float);

                IF server_version >= 14 THEN
                    RETURN jsonb_build_object(
                        'errors', jsonb_build_array(
                            jsonb_build_object(
                                'message', 'pg_graphql extension is not enabled.'
                            )
                        )
                    );
                ELSE
                    RETURN jsonb_build_object(
                        'errors', jsonb_build_array(
                            jsonb_build_object(
                                'message', 'pg_graphql is only available on projects running Postgres 14 onwards.'
                            )
                        )
                    );
                END IF;
            END;
        $$;
    END IF;

    END;
$_$;


--
-- Name: FUNCTION set_graphql_placeholder(); Type: COMMENT; Schema: extensions; Owner: -
--

COMMENT ON FUNCTION extensions.set_graphql_placeholder() IS 'Reintroduces placeholder function for graphql_public.graphql';


--
-- Name: get_auth(text); Type: FUNCTION; Schema: pgbouncer; Owner: -
--

CREATE FUNCTION pgbouncer.get_auth(p_usename text) RETURNS TABLE(username text, password text)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO ''
    AS $_$
  BEGIN
      RAISE DEBUG 'PgBouncer auth request: %', p_usename;

      RETURN QUERY
      SELECT
          rolname::text,
          CASE WHEN rolvaliduntil < now()
              THEN null
              ELSE rolpassword::text
          END
      FROM pg_authid
      WHERE rolname=$1 and rolcanlogin;
  END;
  $_$;


--
-- Name: activate_rental(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.activate_rental(p_booking_id uuid) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  v_caller_id UUID := auth.uid();
  v_renter_id UUID;
  v_owner_id UUID;
BEGIN
  SELECT br.renter_id, e.owner_id INTO v_renter_id, v_owner_id
  FROM booking_requests br
  JOIN equipment e ON br.equipment_id = e.id
  WHERE br.id = p_booking_id;

  IF v_renter_id IS NULL OR v_owner_id IS NULL THEN
    RAISE EXCEPTION 'Booking not found: %', p_booking_id;
  END IF;

  IF v_caller_id IS NULL OR (v_caller_id != v_renter_id AND v_caller_id != v_owner_id) THEN
    RAISE EXCEPTION 'Unauthorized: user does not have permission to activate this rental';
  END IF;

  UPDATE booking_requests
  SET
    status = 'active',
    activated_at = NOW(),
    updated_at = NOW()
  WHERE id = p_booking_id
  AND status = 'approved';

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Could not activate booking. Current status may not be "approved".';
  END IF;

  INSERT INTO rental_events (booking_id, event_type, created_by, event_data)
  VALUES (
    p_booking_id,
    'rental_started',
    v_caller_id,
    jsonb_build_object('activated_at', NOW())
  );
END;
$$;


--
-- Name: FUNCTION activate_rental(p_booking_id uuid); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.activate_rental(p_booking_id uuid) IS 'Activates a rental after pickup inspection. Uses SECURITY DEFINER to atomically update booking_requests and insert into rental_events audit trail. Authorization: caller must be renter or equipment owner.';


--
-- Name: archive_notification(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.archive_notification(p_notification_id uuid) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  v_updated BOOLEAN;
BEGIN
  UPDATE notifications 
  SET is_archived = TRUE, archived_at = NOW()
  WHERE id = p_notification_id 
    AND user_id = auth.uid()
    AND NOT is_archived
  RETURNING TRUE INTO v_updated;
  
  RETURN COALESCE(v_updated, FALSE);
END;
$$;


--
-- Name: FUNCTION archive_notification(p_notification_id uuid); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.archive_notification(p_notification_id uuid) IS 'Archive a notification for the authenticated user';


--
-- Name: archive_old_notifications(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.archive_old_notifications() RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  v_archived INTEGER;
  v_deleted INTEGER;
  v_role TEXT;
BEGIN
  v_role := current_setting('request.jwt.claims', true)::json->>'role';
  IF v_role IS DISTINCT FROM 'service_role' THEN
    RAISE EXCEPTION 'Only service_role can call this function';
  END IF;

  UPDATE notifications
  SET is_archived = TRUE, archived_at = NOW()
  WHERE created_at < NOW() - INTERVAL '30 days'
    AND NOT is_archived;

  GET DIAGNOSTICS v_archived = ROW_COUNT;

  DELETE FROM notifications
  WHERE archived_at < NOW() - INTERVAL '60 days';

  GET DIAGNOSTICS v_deleted = ROW_COUNT;

  RAISE NOTICE 'Archived % notifications, deleted % old archived notifications', v_archived, v_deleted;

  RETURN v_archived + v_deleted;
END;
$$;


--
-- Name: FUNCTION archive_old_notifications(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.archive_old_notifications() IS 'Archive notifications older than 30 days and delete those archived more than 60 days ago';


--
-- Name: calculate_trust_score(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.calculate_trust_score(user_uuid uuid) RETURNS integer
    LANGUAGE plpgsql
    SET search_path TO 'public'
    AS $$
DECLARE
  verification_score INTEGER := 0;
  reviews_score INTEGER := 0;
  bookings_score INTEGER := 0;
  response_score INTEGER := 0;
  account_age_score INTEGER := 0;
  total_score INTEGER := 0;
  profile_rec RECORD;
  avg_rating DECIMAL;
  review_count INTEGER;
  completed_bookings INTEGER;
  avg_response_hours DECIMAL;
  account_days INTEGER;
BEGIN
  SELECT * INTO profile_rec FROM profiles WHERE id = user_uuid;
  IF NOT FOUND THEN RETURN 0; END IF;

  IF profile_rec.identity_verified THEN verification_score := verification_score + 15; END IF;
  IF profile_rec.phone_verified THEN verification_score := verification_score + 8; END IF;
  IF profile_rec.email_verified THEN verification_score := verification_score + 7; END IF;

  SELECT AVG(rating), COUNT(*) INTO avg_rating, review_count
  FROM reviews WHERE reviewee_id = user_uuid;

  IF review_count > 0 THEN
    reviews_score := LEAST(ROUND((avg_rating / 5) * 20)::INTEGER, 20);
    reviews_score := reviews_score + LEAST(review_count, 5);
  END IF;

  SELECT COUNT(*) INTO completed_bookings
  FROM booking_requests br
  LEFT JOIN equipment e ON e.id = br.equipment_id
  WHERE br.status = 'completed'
    AND (br.renter_id = user_uuid OR e.owner_id = user_uuid);

  bookings_score := LEAST(completed_bookings * 2, 20);

  avg_response_hours := COALESCE(profile_rec.average_response_time_hours, 24);
  IF avg_response_hours <= 6 THEN response_score := 15;
  ELSIF avg_response_hours <= 12 THEN response_score := 12;
  ELSIF avg_response_hours <= 24 THEN response_score := 10;
  ELSE response_score := 5;
  END IF;

  account_days := EXTRACT(DAY FROM (NOW() - profile_rec.created_at))::INTEGER;
  account_age_score := LEAST(ROUND((account_days::DECIMAL / 365) * 10)::INTEGER, 10);

  total_score := verification_score + reviews_score + bookings_score + response_score + account_age_score;

  RETURN total_score;
END;
$$;


--
-- Name: calculate_user_response_time(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.calculate_user_response_time(user_uuid uuid) RETURNS numeric
    LANGUAGE plpgsql
    SET search_path TO 'public'
    AS $$
DECLARE
  avg_time DECIMAL(5,2);
BEGIN
  WITH user_conversations AS (
    SELECT c.id as conversation_id
    FROM conversations c
    JOIN conversation_participants cp ON cp.conversation_id = c.id
    WHERE cp.profile_id = user_uuid
  ),
  response_times AS (
    SELECT
      m1.id as incoming_msg_id,
      m1.created_at as incoming_time,
      MIN(m2.created_at) as reply_time
    FROM messages m1
    JOIN user_conversations uc ON m1.conversation_id = uc.conversation_id
    JOIN messages m2 ON m2.conversation_id = m1.conversation_id
      AND m2.sender_id = user_uuid
      AND m2.created_at > m1.created_at
    WHERE m1.sender_id != user_uuid
    GROUP BY m1.id, m1.created_at
  )
  SELECT AVG(EXTRACT(EPOCH FROM (reply_time - incoming_time)) / 3600)::DECIMAL(5,2)
  INTO avg_time
  FROM response_times;

  RETURN COALESCE(avg_time, 24);
END;
$$;


--
-- Name: check_booking_conflicts(uuid, date, date, uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.check_booking_conflicts(p_equipment_id uuid, p_start_date date, p_end_date date, p_exclude_booking_id uuid DEFAULT NULL::uuid) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  conflict_count INTEGER;
BEGIN
  SELECT COUNT(*)
  INTO conflict_count
  FROM booking_requests
  WHERE equipment_id = p_equipment_id
    AND status IN ('pending', 'approved')
    AND (p_exclude_booking_id IS NULL OR id != p_exclude_booking_id)
    AND (
      (start_date <= p_end_date AND end_date >= p_start_date)
    );
  
  RETURN conflict_count = 0;
END;
$$;


--
-- Name: cleanup_stale_pending_bookings(integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.cleanup_stale_pending_bookings(timeout_minutes integer DEFAULT 30) RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    WITH deleted AS (
        DELETE FROM booking_requests
        WHERE status = 'pending'
        AND created_at < NOW() - (timeout_minutes || ' minutes')::INTERVAL
        RETURNING id
    )
    SELECT COUNT(*) INTO deleted_count FROM deleted;
    
    RETURN deleted_count;
END;
$$;


--
-- Name: FUNCTION cleanup_stale_pending_bookings(timeout_minutes integer); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.cleanup_stale_pending_bookings(timeout_minutes integer) IS 'Cleans up abandoned pending booking requests older than the specified timeout. 
     Should be called by a scheduled cron job, not directly by users.';


--
-- Name: complete_onboarding(uuid, text, text, text, text[]); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.complete_onboarding(p_user_id uuid, p_role text, p_location text, p_experience_level text, p_interests text[]) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  v_preferences JSONB;
  v_business_info JSONB;
  v_caller_id UUID;
  v_user_email TEXT;
  v_existing_profile_id UUID;
BEGIN
  -- Authorization check: Only allow users to update their own profile
  -- Service role (Edge Functions) has auth.uid() = null, which is allowed
  -- Regular users must match p_user_id to their auth.uid()
  v_caller_id := auth.uid();
  IF v_caller_id IS NOT NULL AND v_caller_id != p_user_id THEN
    RETURN jsonb_build_object(
      'success', false,
      'error', 'Unauthorized: Cannot modify another user''s profile.'
    );
  END IF;

  -- Validate role
  IF p_role NOT IN ('renter', 'owner') THEN
    RETURN jsonb_build_object('success', false, 'error', 'Invalid role. Must be renter or owner.');
  END IF;

  -- Get user email from auth.users (needed if profile doesn't exist)
  SELECT email INTO v_user_email
  FROM auth.users
  WHERE id = p_user_id;

  IF v_user_email IS NULL THEN
    RETURN jsonb_build_object('success', false, 'error', 'User not found in auth system.');
  END IF;

  -- Check if a profile exists with this email but different ID
  -- This indicates an orphaned profile (not linked to any auth user)
  SELECT id INTO v_existing_profile_id
  FROM public.profiles
  WHERE email = v_user_email AND id != p_user_id;

  -- If orphaned profile exists, delete it (CASCADE will handle related records)
  IF v_existing_profile_id IS NOT NULL THEN
    DELETE FROM public.profiles WHERE id = v_existing_profile_id;
  END IF;

  -- Build preferences JSON for renters
  v_preferences := jsonb_build_object(
    'location', p_location,
    'interests', to_jsonb(p_interests)
  );

  -- Build business_info JSON for owners
  v_business_info := jsonb_build_object('location', p_location);

  -- 1. Upsert profiles table (create if doesn't exist, update if it does)
  INSERT INTO public.profiles (id, email, role, created_at, updated_at)
  VALUES (
    p_user_id,
    v_user_email,
    p_role::public.user_role,
    now(),
    now()
  )
  ON CONFLICT (id) DO UPDATE
  SET role = EXCLUDED.role,
      email = EXCLUDED.email,
      updated_at = now();

  -- 2. Create role-specific profile based on selected role (single-role model)
  IF p_role = 'renter' THEN
    -- Upsert renter_profiles
    INSERT INTO public.renter_profiles (
      profile_id,
      experience_level,
      preferences,
      created_at,
      updated_at
    )
    VALUES (
      p_user_id,
      p_experience_level,
      v_preferences,
      now(),
      now()  -- Fixed: was missing this value
    )
    ON CONFLICT (profile_id) DO UPDATE
    SET experience_level = EXCLUDED.experience_level,
        preferences = EXCLUDED.preferences,
        updated_at = now();

  ELSIF p_role = 'owner' THEN
    -- Upsert owner_profiles
    INSERT INTO public.owner_profiles (
      profile_id,
      business_info,
      earnings_total,
      created_at,
      updated_at
    )
    VALUES (
      p_user_id,
      v_business_info,
      0,
      now(),
      now()  -- Fixed: was missing this value
    )
    ON CONFLICT (profile_id) DO UPDATE
    SET business_info = EXCLUDED.business_info,
        updated_at = now();
  END IF;

  RETURN jsonb_build_object('success', true);

EXCEPTION
  WHEN OTHERS THEN
    RAISE WARNING 'complete_onboarding error for user %: % (SQLSTATE: %)',
      p_user_id, SQLERRM, SQLSTATE;
    RETURN jsonb_build_object(
      'success', false,
      'error', SQLERRM,
      'sqlstate', SQLSTATE
    );
END;
$$;


--
-- Name: FUNCTION complete_onboarding(p_user_id uuid, p_role text, p_location text, p_experience_level text, p_interests text[]); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.complete_onboarding(p_user_id uuid, p_role text, p_location text, p_experience_level text, p_interests text[]) IS 'Atomically completes user onboarding by creating or updating profiles, renter_profiles, and optionally owner_profiles in a single transaction. Handles cases where profile doesn''t exist or exists with different ID (orphaned profiles are deleted).';


--
-- Name: complete_rental(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.complete_rental(p_booking_id uuid) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  v_caller_id UUID := auth.uid();
  v_renter_id UUID;
  v_owner_id UUID;
BEGIN
  SELECT br.renter_id, e.owner_id INTO v_renter_id, v_owner_id
  FROM booking_requests br
  JOIN equipment e ON br.equipment_id = e.id
  WHERE br.id = p_booking_id;

  IF v_renter_id IS NULL OR v_owner_id IS NULL THEN
    RAISE EXCEPTION 'Booking not found: %', p_booking_id;
  END IF;

  IF v_caller_id IS NULL OR (v_caller_id != v_renter_id AND v_caller_id != v_owner_id) THEN
    RAISE EXCEPTION 'Unauthorized: user does not have permission to complete this rental';
  END IF;

  UPDATE booking_requests
  SET
    status = 'completed',
    completed_at = NOW(),
    updated_at = NOW()
  WHERE id = p_booking_id
  AND status = 'active';

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Could not complete booking. Current status may not be "active".';
  END IF;

  INSERT INTO rental_events (booking_id, event_type, created_by, event_data)
  VALUES (
    p_booking_id,
    'rental_completed',
    v_caller_id,
    jsonb_build_object('completed_at', NOW())
  );
END;
$$;


--
-- Name: FUNCTION complete_rental(p_booking_id uuid); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.complete_rental(p_booking_id uuid) IS 'Completes a rental after return inspection. Uses SECURITY DEFINER to atomically update booking_requests and insert into rental_events audit trail. Authorization: caller must be renter or equipment owner.';


--
-- Name: create_default_notification_preferences(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.create_default_notification_preferences() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  INSERT INTO notification_preferences (user_id)
  VALUES (NEW.id)
  ON CONFLICT (user_id) DO NOTHING;
  RETURN NEW;
END;
$$;


--
-- Name: create_notification(uuid, public.notification_type, text, text, text, uuid, uuid, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.create_notification(p_user_id uuid, p_type public.notification_type, p_title text, p_message text, p_related_entity_type text DEFAULT NULL::text, p_related_entity_id uuid DEFAULT NULL::uuid, p_actor_id uuid DEFAULT NULL::uuid, p_group_key text DEFAULT NULL::text) RETURNS uuid
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  v_notification_id UUID;
  v_priority notification_priority;
  v_category TEXT;
  v_pref_enabled BOOLEAN;
BEGIN
  v_category := CASE
    WHEN p_type IN ('booking_confirmed', 'booking_cancelled', 'booking_completed', 'booking_reminder') THEN 'booking'
    WHEN p_type = 'new_message' THEN 'message'
    WHEN p_type IN ('payment_received', 'payment_processed', 'payout_sent', 'refund_issued') THEN 'payment'
    WHEN p_type = 'review_received' THEN 'review'
    WHEN p_type IN ('verification_approved', 'verification_rejected', 'verification_reminder') THEN 'verification'
    WHEN p_type IN ('equipment_favorited', 'equipment_views_milestone') THEN 'equipment'
    WHEN p_type = 'system_announcement' THEN 'system'
    WHEN p_type = 'promotion' THEN 'promotion'
    ELSE 'system'
  END;

  SELECT CASE v_category
    WHEN 'booking' THEN np.booking_notifications
    WHEN 'message' THEN np.message_notifications
    WHEN 'payment' THEN np.payment_notifications
    WHEN 'review' THEN np.review_notifications
    WHEN 'verification' THEN np.verification_notifications
    WHEN 'equipment' THEN np.equipment_notifications
    WHEN 'system' THEN np.system_notifications
    WHEN 'promotion' THEN np.promotion_notifications
    ELSE TRUE
  END INTO v_pref_enabled
  FROM notification_preferences np
  WHERE np.user_id = p_user_id;

  IF v_pref_enabled IS NULL THEN
    v_pref_enabled := TRUE;
  END IF;

  IF v_pref_enabled THEN
    v_priority := CASE
      WHEN p_type IN ('booking_cancelled', 'payment_received', 'refund_issued') THEN 'high'::notification_priority
      WHEN p_type IN ('booking_confirmed', 'booking_completed', 'payout_sent', 'verification_approved', 'verification_rejected') THEN 'medium'::notification_priority
      WHEN p_type IN ('new_message', 'review_received', 'booking_reminder') THEN 'medium'::notification_priority
      WHEN p_type IN ('equipment_favorited', 'equipment_views_milestone', 'promotion') THEN 'low'::notification_priority
      ELSE 'low'::notification_priority
    END;

    INSERT INTO notifications (
      user_id,
      type,
      priority,
      title,
      message,
      related_entity_type,
      related_entity_id,
      actor_id,
      group_key
    ) VALUES (
      p_user_id,
      p_type,
      v_priority,
      p_title,
      p_message,
      p_related_entity_type,
      p_related_entity_id,
      p_actor_id,
      p_group_key
    )
    RETURNING id INTO v_notification_id;

    RETURN v_notification_id;
  END IF;

  RETURN NULL;
END;
$$;


--
-- Name: delete_notification(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.delete_notification(p_notification_id uuid) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  v_deleted BOOLEAN;
BEGIN
  DELETE FROM notifications 
  WHERE id = p_notification_id 
    AND user_id = auth.uid()
  RETURNING TRUE INTO v_deleted;
  
  RETURN COALESCE(v_deleted, FALSE);
END;
$$;


--
-- Name: FUNCTION delete_notification(p_notification_id uuid); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.delete_notification(p_notification_id uuid) IS 'Delete a notification for the authenticated user';


--
-- Name: get_notification_count(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.get_notification_count() RETURNS integer
    LANGUAGE sql STABLE
    SET search_path TO 'public'
    AS $$
  SELECT COUNT(*)::INTEGER
  FROM notifications
  WHERE user_id = auth.uid()
    AND NOT is_read
    AND NOT is_archived;
$$;


--
-- Name: FUNCTION get_notification_count(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.get_notification_count() IS 'Returns the count of unread, non-archived notifications for the authenticated user';


--
-- Name: get_notification_priority(public.notification_type); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.get_notification_priority(p_type public.notification_type) RETURNS public.notification_priority
    LANGUAGE plpgsql IMMUTABLE
    SET search_path TO 'public'
    AS $$
BEGIN
  RETURN CASE p_type
    WHEN 'payment_received' THEN 'critical'::notification_priority
    WHEN 'payout_sent' THEN 'critical'::notification_priority
    WHEN 'refund_issued' THEN 'critical'::notification_priority
    WHEN 'booking_confirmed' THEN 'high'::notification_priority
    WHEN 'booking_cancelled' THEN 'high'::notification_priority
    WHEN 'booking_completed' THEN 'high'::notification_priority
    WHEN 'review_received' THEN 'high'::notification_priority
    WHEN 'verification_approved' THEN 'high'::notification_priority
    WHEN 'verification_rejected' THEN 'high'::notification_priority
    WHEN 'new_message' THEN 'medium'::notification_priority
    WHEN 'booking_reminder' THEN 'medium'::notification_priority
    WHEN 'verification_reminder' THEN 'medium'::notification_priority
    WHEN 'system_announcement' THEN 'medium'::notification_priority
    WHEN 'equipment_favorited' THEN 'low'::notification_priority
    WHEN 'equipment_views_milestone' THEN 'low'::notification_priority
    WHEN 'promotion' THEN 'low'::notification_priority
    ELSE 'medium'::notification_priority
  END;
END;
$$;


--
-- Name: get_notifications(integer, integer, boolean, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.get_notifications(p_limit integer DEFAULT 20, p_offset integer DEFAULT 0, p_include_archived boolean DEFAULT false, p_category text DEFAULT NULL::text) RETURNS TABLE(id uuid, user_id uuid, type public.notification_type, priority public.notification_priority, title text, message text, related_entity_type text, related_entity_id uuid, actor_id uuid, is_read boolean, read_at timestamp with time zone, is_archived boolean, archived_at timestamp with time zone, group_key text, created_at timestamp with time zone, actor_email text, actor_avatar_url text)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  IF p_limit < 1 OR p_limit > 100 THEN
    RAISE EXCEPTION 'Limit must be between 1 and 100';
  END IF;

  IF p_offset < 0 THEN
    RAISE EXCEPTION 'Offset must be non-negative';
  END IF;

  RETURN QUERY
  SELECT 
    n.id,
    n.user_id,
    n.type,
    n.priority,
    n.title,
    n.message,
    n.related_entity_type,
    n.related_entity_id,
    n.actor_id,
    n.is_read,
    n.read_at,
    n.is_archived,
    n.archived_at,
    n.group_key,
    n.created_at,
    p.email AS actor_email,
    p.avatar_url AS actor_avatar_url
  FROM notifications n
  LEFT JOIN profiles p ON p.id = n.actor_id
  WHERE n.user_id = auth.uid()
    AND (p_include_archived OR NOT n.is_archived)
    AND (p_category IS NULL OR 
         (p_category = 'booking' AND n.type IN ('booking_confirmed', 'booking_cancelled', 'booking_completed', 'booking_reminder')) OR
         (p_category = 'message' AND n.type = 'new_message') OR
         (p_category = 'payment' AND n.type IN ('payment_received', 'payment_processed', 'payout_sent', 'refund_issued')) OR
         (p_category = 'review' AND n.type = 'review_received') OR
         (p_category = 'verification' AND n.type IN ('verification_approved', 'verification_rejected', 'verification_reminder')) OR
         (p_category = 'equipment' AND n.type IN ('equipment_favorited', 'equipment_views_milestone')) OR
         (p_category = 'system' AND n.type IN ('system_announcement', 'promotion'))
    )
  ORDER BY n.created_at DESC
  LIMIT p_limit
  OFFSET p_offset;
END;
$$;


--
-- Name: FUNCTION get_notifications(p_limit integer, p_offset integer, p_include_archived boolean, p_category text); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.get_notifications(p_limit integer, p_offset integer, p_include_archived boolean, p_category text) IS 'Get paginated notifications with optional category filter and actor info';


--
-- Name: get_unread_messages_count(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.get_unread_messages_count() RETURNS integer
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'pg_temp', 'public'
    AS $$
  SELECT COALESCE(SUM(unread_count), 0)::integer
  FROM public.messaging_conversation_summaries
  WHERE participant_id = auth.uid()
    AND unread_count > 0;
$$;


--
-- Name: FUNCTION get_unread_messages_count(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.get_unread_messages_count() IS 'Returns the total count of unread messages for the authenticated user across all conversations';


--
-- Name: get_user_role(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.get_user_role(user_id uuid) RETURNS public.user_role
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
    RETURN (
        SELECT role FROM profiles 
        WHERE id = user_id
    );
END;
$$;


--
-- Name: handle_booking_approval(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.handle_booking_approval() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  date_range_days INTEGER;
  max_booking_days INTEGER := 30;
  payment_status_value TEXT;
BEGIN
  IF NEW.status = 'approved' AND (OLD.status IS NULL OR OLD.status != 'approved') THEN
    
    date_range_days := (NEW.end_date - NEW.start_date) + 1;
    IF date_range_days > max_booking_days THEN
      RAISE EXCEPTION 'Booking date range exceeds maximum allowed period of % days', max_booking_days;
    END IF;
    
    IF NEW.end_date < NEW.start_date THEN
      RAISE EXCEPTION 'Invalid date range: end_date must be after start_date';
    END IF;
    
    SELECT COALESCE(
      (SELECT payment_status 
       FROM payments 
       WHERE booking_request_id = NEW.id 
       ORDER BY created_at DESC 
       LIMIT 1),
      'pending'
    ) INTO payment_status_value;
    
    INSERT INTO bookings (booking_request_id, payment_status, return_status)
    VALUES (NEW.id, payment_status_value, 'pending')
    ON CONFLICT (booking_request_id) DO UPDATE
    SET payment_status = payment_status_value;
    
    INSERT INTO availability_calendar (equipment_id, date, is_available)
    SELECT NEW.equipment_id, date_series::date, false
    FROM generate_series(NEW.start_date, NEW.end_date, '1 day'::interval) AS date_series
    ON CONFLICT (equipment_id, date)
    DO UPDATE SET is_available = false;
    
  END IF;
  
  RETURN NEW;
END;
$$;


--
-- Name: handle_booking_cancellation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.handle_booking_cancellation() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public', 'pg_temp'
    AS $$
BEGIN
  -- Only process if status changed from 'approved' to 'declined' or 'cancelled'
  IF (NEW.status = 'declined' OR NEW.status = 'cancelled') 
     AND OLD.status = 'approved' THEN
    
    -- Mark dates as available again in availability_calendar
    -- Use set-based operation to generate date series and UPSERT all dates at once
    -- Recompute availability: set to false if any approved booking still covers the date, otherwise true
    INSERT INTO availability_calendar (equipment_id, date, is_available)
    SELECT 
      OLD.equipment_id,
      date_series::DATE,
      true
    FROM generate_series(OLD.start_date, OLD.end_date, INTERVAL '1 day') AS date_series
    ON CONFLICT (equipment_id, date)
    DO UPDATE SET is_available = (
      NOT EXISTS (
        SELECT 1 
        FROM booking_requests br
        WHERE br.equipment_id = availability_calendar.equipment_id
          AND br.status = 'approved'
          AND br.start_date <= availability_calendar.date
          AND br.end_date >= availability_calendar.date
          AND br.id != OLD.id
      )
    );
    
    -- Note: We keep the bookings record for history/audit purposes
    -- If you want to delete it, uncomment the following:
    -- DELETE FROM bookings WHERE booking_request_id = OLD.id;
    
  END IF;
  
  RETURN NEW;
END;
$$;


--
-- Name: handle_booking_completion(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.handle_booking_completion() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  IF NEW.status::text = 'completed' AND (OLD.status IS NULL OR OLD.status::text != 'completed') THEN
    UPDATE availability_calendar
    SET is_available = true
    FROM generate_series(OLD.start_date, OLD.end_date, '1 day'::interval) AS date_series
    WHERE availability_calendar.equipment_id = OLD.equipment_id
      AND availability_calendar.date = date_series::date;
  END IF;
  
  RETURN NEW;
END;
$$;


--
-- Name: handle_new_user(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.handle_new_user() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public', 'auth'
    AS $$
DECLARE
  user_role text;
BEGIN
  -- Get role from user metadata, default to 'renter'
  user_role := COALESCE(NEW.raw_user_meta_data->>'role', 'renter');
  
  -- SECURITY: Explicitly reject admin role assignment during signup
  -- Admin roles can only be assigned through the admin-users edge function
  -- This prevents privilege escalation via signup metadata manipulation
  IF user_role = 'admin' THEN
    RAISE WARNING 'Admin role cannot be assigned during signup. User % will be created as renter.', NEW.id;
    user_role := 'renter';
  END IF;

  -- Create base profile
  -- SECURITY DEFINER allows this function to bypass RLS policies
  IF user_role = 'owner' THEN
    INSERT INTO public.profiles (id, email, role, created_at, updated_at)
    VALUES (
      NEW.id,
      NEW.email,
      'owner'::public.user_role,
      now(),
      now()
    );
  ELSE
    INSERT INTO public.profiles (id, email, role, created_at, updated_at)
    VALUES (
      NEW.id,
      NEW.email,
      'renter'::public.user_role,
      now(),
      now()
    );
  END IF;

  -- Create role-specific profile
  IF user_role = 'renter' THEN
    INSERT INTO public.renter_profiles (
      profile_id,
      preferences,
      experience_level,
      created_at,
      updated_at
    )
    VALUES (
      NEW.id,
      COALESCE((NEW.raw_user_meta_data->>'preferences')::jsonb, '{}'::jsonb),
      COALESCE(NEW.raw_user_meta_data->>'experienceLevel', 'beginner'),
      now(),
      now()
    );

  ELSIF user_role = 'owner' THEN
    INSERT INTO public.owner_profiles (
      profile_id,
      business_info,
      earnings_total,
      created_at,
      updated_at
    )
    VALUES (
      NEW.id,
      COALESCE((NEW.raw_user_meta_data->>'business_info')::jsonb, '{}'::jsonb),
      0,
      now(),
      now()
    );
  END IF;

  RETURN NEW;

EXCEPTION
  WHEN OTHERS THEN
    -- Log the error but don't prevent user creation
    -- This ensures auth.users record is still created even if profile creation fails
    RAISE WARNING 'Error in handle_new_user for user %: % (SQLSTATE: %)',
      NEW.id, SQLERRM, SQLSTATE;
    RETURN NEW;
END;
$$;


--
-- Name: FUNCTION handle_new_user(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.handle_new_user() IS 'Automatically creates profile and role-specific profile (renter/owner) when a new user signs up. Uses SECURITY DEFINER to bypass RLS policies during profile creation. Explicitly rejects admin role assignment during signup - admin roles can only be assigned through the admin-users edge function.';


--
-- Name: is_admin(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.is_admin(user_id uuid) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public', 'pg_catalog'
    AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM public.profiles
        WHERE id = user_id AND role = 'admin'
    );
END;
$$;


--
-- Name: is_conversation_participant(uuid, uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.is_conversation_participant(conv_id uuid, user_id uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  SELECT EXISTS (
    SELECT 1 FROM conversation_participants
    WHERE conversation_id = conv_id AND profile_id = user_id
  );
$$;


--
-- Name: FUNCTION is_conversation_participant(conv_id uuid, user_id uuid); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.is_conversation_participant(conv_id uuid, user_id uuid) IS 'Check if a user is a participant in a conversation. Uses SECURITY DEFINER to bypass RLS and prevent infinite recursion.';


--
-- Name: is_equipment_owner(uuid, uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.is_equipment_owner(equipment_id uuid, user_id uuid) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
    RETURN (
        SELECT EXISTS (
            SELECT 1 FROM equipment 
            WHERE id = equipment_id 
            AND owner_id = user_id
        )
    );
END;
$$;


--
-- Name: is_user_in_conversation_participants(uuid, uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.is_user_in_conversation_participants(conv_id uuid, user_id uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  SELECT EXISTS (
    SELECT 1 FROM conversations
    WHERE id = conv_id
    AND user_id = ANY(participants)
  );
$$;


--
-- Name: log_booking_status_change(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.log_booking_status_change() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  IF NEW.status IS DISTINCT FROM OLD.status THEN
    INSERT INTO booking_history (
      booking_request_id,
      old_status,
      new_status,
      changed_by,
      reason
    )
    VALUES (
      NEW.id,
      OLD.status,
      NEW.status,
      auth.uid(),
      NULL
    );
  END IF;
  
  RETURN NEW;
END;
$$;


--
-- Name: mark_all_notifications_read(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mark_all_notifications_read() RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  v_count INTEGER;
BEGIN
  UPDATE notifications 
  SET is_read = TRUE, read_at = NOW()
  WHERE user_id = auth.uid()
    AND NOT is_read 
    AND NOT is_archived;
  
  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count;
END;
$$;


--
-- Name: FUNCTION mark_all_notifications_read(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.mark_all_notifications_read() IS 'Mark all unread notifications as read for the authenticated user';


--
-- Name: mark_conversation_read(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mark_conversation_read(p_conversation uuid) RETURNS void
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  UPDATE public.conversation_participants
  SET last_read_at = NOW()
  WHERE conversation_id = p_conversation
    AND profile_id = auth.uid();
$$;


--
-- Name: mark_notification_read(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mark_notification_read(p_notification_id uuid) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  v_updated BOOLEAN;
BEGIN
  UPDATE notifications 
  SET is_read = TRUE, read_at = NOW()
  WHERE id = p_notification_id 
    AND user_id = auth.uid()
    AND NOT is_read
  RETURNING TRUE INTO v_updated;
  
  RETURN COALESCE(v_updated, FALSE);
END;
$$;


--
-- Name: FUNCTION mark_notification_read(p_notification_id uuid); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.mark_notification_read(p_notification_id uuid) IS 'Mark a single notification as read for the authenticated user';


--
-- Name: notify_admins_on_verification_submitted(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.notify_admins_on_verification_submitted() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  v_admin_id UUID;
  v_user_name TEXT;
  v_type_label TEXT;
BEGIN
  IF NEW.status != 'pending' OR (OLD.status = 'pending' AND TG_OP = 'UPDATE') THEN
    RETURN NEW;
  END IF;

  SELECT COALESCE(full_name, email, 'A user')
  INTO v_user_name
  FROM profiles
  WHERE id = NEW.user_id;

  v_type_label := CASE NEW.verification_type
    WHEN 'identity' THEN 'Identity'
    WHEN 'phone' THEN 'Phone'
    WHEN 'email' THEN 'Email'
    WHEN 'address' THEN 'Address'
    ELSE NEW.verification_type
  END;

  FOR v_admin_id IN
    SELECT id FROM profiles WHERE role = 'admin'
  LOOP
    PERFORM create_notification(
      v_admin_id,
      'verification_submitted'::notification_type,
      'Verification Submitted',
      format('%s submitted %s verification for review', v_user_name, v_type_label),
      'verification',
      NEW.id,
      NEW.user_id,
      format('verification:%s', NEW.id)
    );
  END LOOP;

  RETURN NEW;
END;
$$;


--
-- Name: notify_conversation_participant_added(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.notify_conversation_participant_added() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  channel text;
BEGIN
  channel := 'user:' || NEW.profile_id::text || ':conversations';

  PERFORM realtime.broadcast_changes(
    channel,
    'participant_added',
    'INSERT',
    TG_TABLE_NAME,
    TG_TABLE_SCHEMA,
    NEW,
    NULL
  );

  RETURN NEW;
END;
$$;


--
-- Name: notify_message_created(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.notify_message_created() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  channel text;
  participant_rec record;
BEGIN
  channel := 'room:' || NEW.conversation_id::text || ':messages';

  PERFORM realtime.broadcast_changes(
    channel,
    'message_created',
    'INSERT',
    TG_TABLE_NAME,
    TG_TABLE_SCHEMA,
    NEW,
    NULL
  );

  FOR participant_rec IN
    SELECT profile_id
    FROM public.conversation_participants
    WHERE conversation_id = NEW.conversation_id
  LOOP
    PERFORM realtime.send(
      jsonb_build_object(
        'conversation_id', NEW.conversation_id,
        'message_id', NEW.id
      ),
      'message_created',
      'user:' || participant_rec.profile_id::text || ':conversations',
      true
    );
  END LOOP;

  RETURN NEW;
END;
$$;


--
-- Name: notify_on_booking_created(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.notify_on_booking_created() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $_$
DECLARE
  v_equipment_title TEXT;
  v_owner_id UUID;
  v_renter_id UUID;
  v_amount NUMERIC;
  v_equipment_id UUID;
BEGIN
  SELECT e.title, e.owner_id, br.renter_id, br.total_amount, br.equipment_id
  INTO v_equipment_title, v_owner_id, v_renter_id, v_amount, v_equipment_id
  FROM booking_requests br
  JOIN equipment e ON e.id = br.equipment_id
  WHERE br.id = NEW.booking_request_id;
  
  IF v_renter_id IS NULL OR v_owner_id IS NULL OR v_equipment_id IS NULL OR v_equipment_title IS NULL THEN
    RETURN NEW;
  END IF;
  
  PERFORM create_notification(
    v_owner_id,
    'booking_confirmed'::notification_type,
    'New Booking Confirmed',
    format('You have a new booking for %s - $%s', v_equipment_title, v_amount),
    'booking',
    NEW.id,
    v_renter_id,
    format('booking:%s', NEW.id)
  );
  
  PERFORM create_notification(
    v_renter_id,
    'booking_confirmed'::notification_type,
    'Booking Confirmed!',
    format('Your booking for %s is confirmed', v_equipment_title),
    'booking',
    NEW.id,
    v_owner_id,
    format('booking:%s', NEW.id)
  );
  
  RETURN NEW;
END;
$_$;


--
-- Name: notify_on_booking_request_cancelled(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.notify_on_booking_request_cancelled() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  v_equipment_title TEXT;
  v_owner_id UUID;
  v_booking_id UUID;
BEGIN
  IF NEW.status != 'cancelled' OR OLD.status = 'cancelled' THEN
    RETURN NEW;
  END IF;

  SELECT id INTO v_booking_id
  FROM bookings
  WHERE booking_request_id = NEW.id;

  SELECT e.title, e.owner_id
  INTO v_equipment_title, v_owner_id
  FROM equipment e
  WHERE e.id = NEW.equipment_id;

  PERFORM create_notification(
    NEW.renter_id,
    'booking_cancelled'::notification_type,
    'Booking Cancelled',
    format('Your booking for %s has been cancelled', v_equipment_title),
    'booking',
    v_booking_id,
    NULL,
    NULL
  );

  PERFORM create_notification(
    v_owner_id,
    'booking_cancelled'::notification_type,
    'Booking Cancelled',
    format('A booking for %s has been cancelled', v_equipment_title),
    'booking',
    v_booking_id,
    NEW.renter_id,
    NULL
  );

  RETURN NEW;
END;
$$;


--
-- Name: notify_on_booking_status_change(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.notify_on_booking_status_change() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  v_equipment_title TEXT;
  v_owner_id UUID;
  v_renter_id UUID;
  v_booking_request RECORD;
BEGIN
  IF OLD.payment_status = NEW.payment_status THEN
    RETURN NEW;
  END IF;
  
  SELECT br.*, e.title AS equipment_title, e.owner_id
  INTO v_booking_request
  FROM booking_requests br
  JOIN equipment e ON e.id = br.equipment_id
  WHERE br.id = NEW.booking_request_id;
  
  v_equipment_title := v_booking_request.equipment_title;
  v_owner_id := v_booking_request.owner_id;
  v_renter_id := v_booking_request.renter_id;
  
  IF NEW.payment_status = 'completed' AND OLD.payment_status != 'completed' THEN
    PERFORM create_notification(
      v_renter_id,
      'booking_completed'::notification_type,
      'Rental Complete!',
      format('Your rental of %s is complete. Leave a review!', v_equipment_title),
      'booking',
      NEW.id,
      v_owner_id,
      NULL
    );
    
    PERFORM create_notification(
      v_owner_id,
      'booking_completed'::notification_type,
      'Rental Completed',
      format('Rental of %s has been completed', v_equipment_title),
      'booking',
      NEW.id,
      v_renter_id,
      NULL
    );
  END IF;
  
  RETURN NEW;
END;
$$;


--
-- Name: notify_on_equipment_favorited(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.notify_on_equipment_favorited() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  v_owner_id UUID;
  v_equipment_title TEXT;
BEGIN
  SELECT e.owner_id, e.title
  INTO v_owner_id, v_equipment_title
  FROM equipment e
  WHERE e.id = NEW.equipment_id;

  IF v_owner_id = NEW.user_id THEN
    RETURN NEW;
  END IF;

  PERFORM create_notification(
    v_owner_id,
    'equipment_favorited'::notification_type,
    'Equipment Favorited',
    format('Someone saved %s to their favorites', v_equipment_title),
    'equipment',
    NEW.equipment_id,
    NEW.user_id,
    format('favorites:%s', NEW.equipment_id)
  );
  
  RETURN NEW;
END;
$$;


--
-- Name: notify_on_new_message(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.notify_on_new_message() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  v_sender_name TEXT;
  v_recipient RECORD;
BEGIN
  IF NEW.message_type != 'text' THEN
    RETURN NEW;
  END IF;

  SELECT COALESCE(full_name, username, 'Someone') INTO v_sender_name
  FROM profiles
  WHERE id = NEW.sender_id;

  FOR v_recipient IN
    SELECT cp.profile_id
    FROM conversation_participants cp
    WHERE cp.conversation_id = NEW.conversation_id
      AND cp.profile_id != NEW.sender_id
  LOOP
    PERFORM create_notification(
      v_recipient.profile_id,
      'new_message'::notification_type,
      'New Message',
      format('New message from %s', v_sender_name),
      'conversation',
      NEW.conversation_id,
      NEW.sender_id,
      format('messages:%s', NEW.conversation_id)
    );
  END LOOP;

  RETURN NEW;
END;
$$;


--
-- Name: notify_on_new_review(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.notify_on_new_review() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  v_reviewer_name TEXT;
BEGIN
  SELECT COALESCE(full_name, username, 'someone') INTO v_reviewer_name
  FROM profiles
  WHERE id = NEW.reviewer_id;

  PERFORM create_notification(
    NEW.reviewee_id,
    'review_received'::notification_type,
    'New Review',
    format('You received a %s-star review from %s', NEW.rating, v_reviewer_name),
    'review',
    NEW.id,
    NEW.reviewer_id,
    NULL
  );

  RETURN NEW;
END;
$$;


--
-- Name: notify_on_payout(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.notify_on_payout() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $_$
DECLARE
  v_owner_id UUID;
  v_equipment_title TEXT;
BEGIN
  IF NEW.payout_status != 'completed' OR OLD.payout_status = 'completed' THEN
    RETURN NEW;
  END IF;
  
  SELECT e.owner_id, e.title
  INTO v_owner_id, v_equipment_title
  FROM booking_requests br
  JOIN equipment e ON e.id = br.equipment_id
  WHERE br.id = NEW.booking_request_id;
  
  PERFORM create_notification(
    v_owner_id,
    'payout_sent'::notification_type,
    'Payout Sent!',
    format('$%s has been sent to your account for %s', NEW.owner_amount, v_equipment_title),
    'payment',
    NEW.id,
    NULL,
    NULL
  );
  
  RETURN NEW;
END;
$_$;


--
-- Name: notify_on_refund(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.notify_on_refund() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $_$
DECLARE
  v_renter_id UUID;
  v_equipment_title TEXT;
BEGIN
  IF NEW.escrow_status != 'refunded' OR OLD.escrow_status = 'refunded' THEN
    RETURN NEW;
  END IF;
  
  SELECT br.renter_id, e.title
  INTO v_renter_id, v_equipment_title
  FROM booking_requests br
  JOIN equipment e ON e.id = br.equipment_id
  WHERE br.id = NEW.booking_request_id;
  
  PERFORM create_notification(
    v_renter_id,
    'refund_issued'::notification_type,
    'Refund Issued',
    format('A refund of $%s has been issued for %s', NEW.total_amount, v_equipment_title),
    'payment',
    NEW.id,
    NULL,
    NULL
  );
  
  RETURN NEW;
END;
$_$;


--
-- Name: prevent_role_escalation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.prevent_role_escalation() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public', 'pg_catalog'
    AS $$
DECLARE
  current_user_id UUID;
  is_admin_user BOOLEAN;
BEGIN
  -- Get current user ID (may be NULL if using service role)
  current_user_id := auth.uid();
  
  -- Prevent changing role to admin unless already admin
  -- This blocks privilege escalation attempts
  IF NEW.role = 'admin' AND (OLD.role IS NULL OR OLD.role != 'admin') THEN
    -- Allow if:
    -- 1. Using service role (current_user_id is NULL) - admin-users edge function
    --    The edge function validates admin access before calling
    -- 2. Current user is already an admin
    -- Regular users cannot escalate their own privileges
    IF current_user_id IS NOT NULL THEN
      is_admin_user := is_admin(current_user_id);
      IF NOT is_admin_user THEN
        RAISE EXCEPTION 'Cannot change role to admin. Admin roles can only be assigned by administrators through the admin dashboard.';
      END IF;
    END IF;
    -- If current_user_id IS NULL, we're using service role (admin-users function)
    -- which has already validated admin access, so allow the change
  END IF;
  
  -- Prevent changing FROM admin (additional safety)
  -- Only admins can demote other admins
  IF OLD.role = 'admin' AND NEW.role != 'admin' THEN
    -- Allow if:
    -- 1. Using service role (admin-users function)
    -- 2. Current user is an admin
    IF current_user_id IS NOT NULL THEN
      is_admin_user := is_admin(current_user_id);
      IF NOT is_admin_user THEN
        RAISE EXCEPTION 'Cannot change admin role. Only administrators can modify admin roles.';
      END IF;
    END IF;
    -- If current_user_id IS NULL, allow (service role from admin-users function)
  END IF;
  
  RETURN NEW;
END;
$$;


--
-- Name: FUNCTION prevent_role_escalation(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.prevent_role_escalation() IS 'Prevents unauthorized role escalation to admin. Only existing admins can assign admin roles. This provides defense-in-depth against privilege escalation attacks.';


--
-- Name: protect_profiles_sensitive_fields(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.protect_profiles_sensitive_fields() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public', 'pg_catalog'
    AS $$
BEGIN
  -- Allow service_role or other contexts without a user JWT
  IF auth.uid() IS NULL THEN
    RETURN NEW;
  END IF;

  -- Allow admins to modify any profile fields
  IF public.is_admin(auth.uid()) THEN
    RETURN NEW;
  END IF;

  -- Non-admins can only update their own profile
  IF auth.uid() <> NEW.id THEN
    RAISE EXCEPTION 'Forbidden';
  END IF;

  -- Only allow self role change for renter -> owner upgrade
  IF NEW.role IS DISTINCT FROM OLD.role THEN
    IF OLD.role = 'renter'::public.user_role AND NEW.role = 'owner'::public.user_role THEN
      NULL;
    ELSE
      RAISE EXCEPTION 'Role change not permitted';
    END IF;
  END IF;

  -- Prevent users from changing their stored email (source of truth is auth.users)
  IF NEW.email IS DISTINCT FROM OLD.email THEN
    RAISE EXCEPTION 'Email change not permitted';
  END IF;

  -- Prevent users from toggling verification flags / timestamps
  IF NEW.identity_verified IS DISTINCT FROM OLD.identity_verified
     OR NEW.phone_verified IS DISTINCT FROM OLD.phone_verified
     OR NEW.email_verified IS DISTINCT FROM OLD.email_verified
     OR NEW.address_verified IS DISTINCT FROM OLD.address_verified
     OR NEW.verified_at IS DISTINCT FROM OLD.verified_at THEN
    RAISE EXCEPTION 'Verification fields can only be updated by an admin';
  END IF;

  -- Prevent users from editing trust score fields directly
  IF NEW.trust_score IS DISTINCT FROM OLD.trust_score
     OR NEW.trust_score_updated_at IS DISTINCT FROM OLD.trust_score_updated_at THEN
    RAISE EXCEPTION 'Trust score can only be updated by the system';
  END IF;

  -- Prevent users from changing created_at
  IF NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'created_at cannot be changed';
  END IF;

  RETURN NEW;
END;
$$;


--
-- Name: set_payout_processed_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.set_payout_processed_at() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'public'
    AS $$
BEGIN
    IF NEW.payout_status = 'completed' AND (OLD.payout_status IS NULL OR OLD.payout_status != 'completed') THEN
        NEW.payout_processed_at := NOW();
    ELSIF NEW.payout_status != 'completed' AND OLD.payout_status = 'completed' THEN
        NEW.payout_processed_at := NULL;
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: sync_existing_profiles_from_auth(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.sync_existing_profiles_from_auth() RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  updated_count INTEGER := 0;
  profile_record RECORD;
  auth_meta JSONB;
BEGIN
  FOR profile_record IN 
    SELECT p.id, p.full_name, p.username, p.avatar_url
    FROM profiles p
    WHERE p.full_name IS NULL OR p.username IS NULL OR p.avatar_url IS NULL
  LOOP
    SELECT raw_user_meta_data INTO auth_meta
    FROM auth.users
    WHERE id = profile_record.id;

    IF auth_meta IS NOT NULL THEN
      UPDATE profiles
      SET 
        full_name = COALESCE(profiles.full_name, auth_meta->>'full_name', auth_meta->>'name'),
        username = COALESCE(profiles.username, auth_meta->>'user_name', auth_meta->>'preferred_username', auth_meta->>'nickname'),
        avatar_url = COALESCE(profiles.avatar_url, auth_meta->>'avatar_url', auth_meta->>'picture')
      WHERE id = profile_record.id
        AND (full_name IS NULL OR username IS NULL OR avatar_url IS NULL);
      
      IF FOUND THEN
        updated_count := updated_count + 1;
      END IF;
    END IF;
  END LOOP;

  RETURN updated_count;
END;
$$;


--
-- Name: sync_payment_status_to_booking(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.sync_payment_status_to_booking() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  IF TG_OP = 'UPDATE' OR TG_OP = 'INSERT' THEN
    UPDATE bookings
    SET payment_status = NEW.payment_status
    WHERE booking_request_id = NEW.booking_request_id;
  END IF;
  
  RETURN NEW;
END;
$$;


--
-- Name: sync_profile_from_auth(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.sync_profile_from_auth() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  auth_user_meta JSONB;
BEGIN
  SELECT raw_user_meta_data INTO auth_user_meta
  FROM auth.users
  WHERE id = NEW.id;

  IF auth_user_meta IS NOT NULL THEN
    IF NEW.full_name IS NULL THEN
      NEW.full_name := COALESCE(
        auth_user_meta->>'full_name',
        auth_user_meta->>'name'
      );
    END IF;

    IF NEW.username IS NULL THEN
      NEW.username := COALESCE(
        auth_user_meta->>'user_name',
        auth_user_meta->>'preferred_username',
        auth_user_meta->>'nickname'
      );
    END IF;

    IF NEW.avatar_url IS NULL THEN
      NEW.avatar_url := COALESCE(
        auth_user_meta->>'avatar_url',
        auth_user_meta->>'picture'
      );
    END IF;
  END IF;

  RETURN NEW;
END;
$$;


--
-- Name: touch_last_seen_on_conversation_read(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.touch_last_seen_on_conversation_read() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  -- profile_id check for safety (trigger WHEN clause guarantees last_read_at IS NOT NULL and value changed)
  IF NEW.profile_id IS NOT NULL THEN
    UPDATE public.profiles
    SET last_seen_at = NOW()
    WHERE id = NEW.profile_id;
  END IF;

  RETURN NEW;
END;
$$;


--
-- Name: touch_last_seen_on_message(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.touch_last_seen_on_message() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  IF NEW.sender_id IS NULL THEN
    RETURN NEW;
  END IF;

  UPDATE public.profiles
  SET last_seen_at = NOW()
  WHERE id = NEW.sender_id 
    AND (last_seen_at IS NULL OR last_seen_at < NOW() - INTERVAL '1 minute');

  RETURN NEW;
END;
$$;


--
-- Name: transition_rentals_to_active(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.transition_rentals_to_active() RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER
    AS $$
DECLARE
  activated_count INTEGER := 0;
  booking_record RECORD;
BEGIN
  -- Find all rentals ready to activate
  FOR booking_record IN
    SELECT br.id
    FROM booking_requests br
    WHERE br.status = 'awaiting_start_date'
    AND br.start_date <= CURRENT_DATE
  LOOP
    -- Update status (trigger will validate transition)
    UPDATE booking_requests
    SET
      status = 'active',
      activated_at = COALESCE(activated_at, now()),
      status_updated_at = now()
    WHERE id = booking_record.id;

    -- Log rental event
    INSERT INTO rental_events (booking_id, event_type, event_data, created_at)
    VALUES (
      booking_record.id,
      'rental_started',
      jsonb_build_object('auto_activated', true, 'activation_date', CURRENT_DATE),
      now()
    );

    -- Create notification for both parties
    INSERT INTO notifications (user_id, type, priority, title, message, related_entity_type, related_entity_id, created_at)
    SELECT
      unnest(ARRAY[br.renter_id, e.owner_id]),
      'booking_confirmed',
      'high',
      'Rental Started',
      'Your rental for ' || e.title || ' has started.',
      'booking',
      br.id,
      now()
    FROM booking_requests br
    JOIN equipment e ON e.id = br.equipment_id
    WHERE br.id = booking_record.id;

    activated_count := activated_count + 1;
  END LOOP;

  RETURN activated_count;
END;
$$;


--
-- Name: FUNCTION transition_rentals_to_active(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.transition_rentals_to_active() IS 'Automatically activates rentals when start_date is reached. Called by pg_cron every hour.';


--
-- Name: trigger_update_response_time_on_message(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trigger_update_response_time_on_message() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'public'
    AS $$
BEGIN
  PERFORM update_user_response_time(NEW.sender_id);
  RETURN NEW;
END;
$$;


--
-- Name: trigger_update_trust_score_on_booking_complete(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trigger_update_trust_score_on_booking_complete() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'public'
    AS $$
DECLARE
  owner_id UUID;
BEGIN
  IF NEW.status = 'completed' AND OLD.status != 'completed' THEN
    PERFORM update_user_trust_score(NEW.renter_id);

    SELECT e.owner_id INTO owner_id
    FROM equipment e WHERE e.id = NEW.equipment_id;

    IF owner_id IS NOT NULL THEN
      PERFORM update_user_trust_score(owner_id);
    END IF;
  END IF;
  RETURN NEW;
END;
$$;


--
-- Name: trigger_update_trust_score_on_review(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trigger_update_trust_score_on_review() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'public'
    AS $$
BEGIN
  PERFORM update_user_trust_score(NEW.reviewee_id);
  RETURN NEW;
END;
$$;


--
-- Name: trigger_update_trust_score_on_verification(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trigger_update_trust_score_on_verification() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'public'
    AS $$
BEGIN
  IF OLD.identity_verified IS DISTINCT FROM NEW.identity_verified
     OR OLD.phone_verified IS DISTINCT FROM NEW.phone_verified
     OR OLD.email_verified IS DISTINCT FROM NEW.email_verified
     OR OLD.address_verified IS DISTINCT FROM NEW.address_verified THEN
    PERFORM update_user_trust_score(NEW.id);
  END IF;
  RETURN NEW;
END;
$$;


--
-- Name: update_content_translations_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_content_translations_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'public'
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


--
-- Name: update_damage_claims_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_damage_claims_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'public'
    AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;


--
-- Name: update_last_seen(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_last_seen() RETURNS void
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  UPDATE public.profiles
  SET last_seen_at = NOW()
  WHERE id = auth.uid();
$$;


--
-- Name: update_payments_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_payments_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'public'
    AS $$
BEGIN 
  NEW.updated_at = now(); 
  RETURN NEW; 
END; 
$$;


--
-- Name: update_updated_at_column(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'public'
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


--
-- Name: update_user_response_time(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_user_response_time(user_uuid uuid) RETURNS void
    LANGUAGE plpgsql
    SET search_path TO 'public'
    AS $$
BEGIN
  UPDATE profiles
  SET
    average_response_time_hours = calculate_user_response_time(user_uuid)
  WHERE id = user_uuid;

  PERFORM update_user_trust_score(user_uuid);
END;
$$;


--
-- Name: update_user_trust_score(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_user_trust_score(user_uuid uuid) RETURNS void
    LANGUAGE plpgsql
    SET search_path TO 'public'
    AS $$
BEGIN
  UPDATE profiles
  SET
    trust_score = calculate_trust_score(user_uuid),
    trust_score_updated_at = NOW()
  WHERE id = user_uuid;
END;
$$;


--
-- Name: validate_booking_status_transition(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.validate_booking_status_transition() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  valid_transitions TEXT[][] := ARRAY[
    -- From pending
    ARRAY['pending', 'paid'],
    ARRAY['pending', 'declined'],
    ARRAY['pending', 'cancelled'],
    -- From paid (transitional, usually skipped)
    ARRAY['paid', 'awaiting_pickup_inspection'],
    ARRAY['paid', 'cancelled'],
    -- From awaiting_pickup_inspection
    ARRAY['awaiting_pickup_inspection', 'awaiting_start_date'],
    ARRAY['awaiting_pickup_inspection', 'cancelled'],
    -- From awaiting_start_date
    ARRAY['awaiting_start_date', 'active'],
    ARRAY['awaiting_start_date', 'cancelled'],
    -- From active
    ARRAY['active', 'awaiting_return_inspection'],
    -- From awaiting_return_inspection
    ARRAY['awaiting_return_inspection', 'pending_owner_review'],
    -- From pending_owner_review
    ARRAY['pending_owner_review', 'completed'],
    ARRAY['pending_owner_review', 'disputed'],
    -- From disputed
    ARRAY['disputed', 'completed'],
    -- Legacy support: approved -> new states (for migration)
    ARRAY['approved', 'awaiting_pickup_inspection'],
    ARRAY['approved', 'awaiting_start_date'],
    ARRAY['approved', 'active'],
    ARRAY['approved', 'cancelled']
  ];
  transition TEXT[];
  is_valid BOOLEAN := FALSE;
BEGIN
  -- Allow if status unchanged
  IF OLD.status = NEW.status THEN
    RETURN NEW;
  END IF;

  -- Check if transition is valid
  FOREACH transition SLICE 1 IN ARRAY valid_transitions
  LOOP
    IF OLD.status::TEXT = transition[1] AND NEW.status::TEXT = transition[2] THEN
      is_valid := TRUE;
      EXIT;
    END IF;
  END LOOP;

  IF NOT is_valid THEN
    RAISE EXCEPTION 'Invalid status transition from % to %', OLD.status, NEW.status
      USING HINT = 'Check valid transitions in validate_booking_status_transition()';
  END IF;

  -- Update timestamp on status change
  NEW.status_updated_at := now();

  -- Set disputed_at when entering disputed state
  IF NEW.status = 'disputed' AND OLD.status != 'disputed' THEN
    NEW.disputed_at := now();
  END IF;

  RETURN NEW;
END;
$$;


--
-- Name: FUNCTION validate_booking_status_transition(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.validate_booking_status_transition() IS 'Validates booking status transitions follow the defined state machine. Prevents invalid state changes.';


--
-- Name: apply_rls(jsonb, integer); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.apply_rls(wal jsonb, max_record_bytes integer DEFAULT (1024 * 1024)) RETURNS SETOF realtime.wal_rls
    LANGUAGE plpgsql
    AS $$
declare
-- Regclass of the table e.g. public.notes
entity_ regclass = (quote_ident(wal ->> 'schema') || '.' || quote_ident(wal ->> 'table'))::regclass;

-- I, U, D, T: insert, update ...
action realtime.action = (
    case wal ->> 'action'
        when 'I' then 'INSERT'
        when 'U' then 'UPDATE'
        when 'D' then 'DELETE'
        else 'ERROR'
    end
);

-- Is row level security enabled for the table
is_rls_enabled bool = relrowsecurity from pg_class where oid = entity_;

subscriptions realtime.subscription[] = array_agg(subs)
    from
        realtime.subscription subs
    where
        subs.entity = entity_
        -- Filter by action early - only get subscriptions interested in this action
        -- action_filter column can be: '*' (all), 'INSERT', 'UPDATE', or 'DELETE'
        and (subs.action_filter = '*' or subs.action_filter = action::text);

-- Subscription vars
roles regrole[] = array_agg(distinct us.claims_role::text)
    from
        unnest(subscriptions) us;

working_role regrole;
claimed_role regrole;
claims jsonb;

subscription_id uuid;
subscription_has_access bool;
visible_to_subscription_ids uuid[] = '{}';

-- structured info for wal's columns
columns realtime.wal_column[];
-- previous identity values for update/delete
old_columns realtime.wal_column[];

error_record_exceeds_max_size boolean = octet_length(wal::text) > max_record_bytes;

-- Primary jsonb output for record
output jsonb;

begin
perform set_config('role', null, true);

columns =
    array_agg(
        (
            x->>'name',
            x->>'type',
            x->>'typeoid',
            realtime.cast(
                (x->'value') #>> '{}',
                coalesce(
                    (x->>'typeoid')::regtype, -- null when wal2json version <= 2.4
                    (x->>'type')::regtype
                )
            ),
            (pks ->> 'name') is not null,
            true
        )::realtime.wal_column
    )
    from
        jsonb_array_elements(wal -> 'columns') x
        left join jsonb_array_elements(wal -> 'pk') pks
            on (x ->> 'name') = (pks ->> 'name');

old_columns =
    array_agg(
        (
            x->>'name',
            x->>'type',
            x->>'typeoid',
            realtime.cast(
                (x->'value') #>> '{}',
                coalesce(
                    (x->>'typeoid')::regtype, -- null when wal2json version <= 2.4
                    (x->>'type')::regtype
                )
            ),
            (pks ->> 'name') is not null,
            true
        )::realtime.wal_column
    )
    from
        jsonb_array_elements(wal -> 'identity') x
        left join jsonb_array_elements(wal -> 'pk') pks
            on (x ->> 'name') = (pks ->> 'name');

for working_role in select * from unnest(roles) loop

    -- Update `is_selectable` for columns and old_columns
    columns =
        array_agg(
            (
                c.name,
                c.type_name,
                c.type_oid,
                c.value,
                c.is_pkey,
                pg_catalog.has_column_privilege(working_role, entity_, c.name, 'SELECT')
            )::realtime.wal_column
        )
        from
            unnest(columns) c;

    old_columns =
            array_agg(
                (
                    c.name,
                    c.type_name,
                    c.type_oid,
                    c.value,
                    c.is_pkey,
                    pg_catalog.has_column_privilege(working_role, entity_, c.name, 'SELECT')
                )::realtime.wal_column
            )
            from
                unnest(old_columns) c;

    if action <> 'DELETE' and count(1) = 0 from unnest(columns) c where c.is_pkey then
        return next (
            jsonb_build_object(
                'schema', wal ->> 'schema',
                'table', wal ->> 'table',
                'type', action
            ),
            is_rls_enabled,
            -- subscriptions is already filtered by entity
            (select array_agg(s.subscription_id) from unnest(subscriptions) as s where claims_role = working_role),
            array['Error 400: Bad Request, no primary key']
        )::realtime.wal_rls;

    -- The claims role does not have SELECT permission to the primary key of entity
    elsif action <> 'DELETE' and sum(c.is_selectable::int) <> count(1) from unnest(columns) c where c.is_pkey then
        return next (
            jsonb_build_object(
                'schema', wal ->> 'schema',
                'table', wal ->> 'table',
                'type', action
            ),
            is_rls_enabled,
            (select array_agg(s.subscription_id) from unnest(subscriptions) as s where claims_role = working_role),
            array['Error 401: Unauthorized']
        )::realtime.wal_rls;

    else
        output = jsonb_build_object(
            'schema', wal ->> 'schema',
            'table', wal ->> 'table',
            'type', action,
            'commit_timestamp', to_char(
                ((wal ->> 'timestamp')::timestamptz at time zone 'utc'),
                'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
            ),
            'columns', (
                select
                    jsonb_agg(
                        jsonb_build_object(
                            'name', pa.attname,
                            'type', pt.typname
                        )
                        order by pa.attnum asc
                    )
                from
                    pg_attribute pa
                    join pg_type pt
                        on pa.atttypid = pt.oid
                where
                    attrelid = entity_
                    and attnum > 0
                    and pg_catalog.has_column_privilege(working_role, entity_, pa.attname, 'SELECT')
            )
        )
        -- Add "record" key for insert and update
        || case
            when action in ('INSERT', 'UPDATE') then
                jsonb_build_object(
                    'record',
                    (
                        select
                            jsonb_object_agg(
                                -- if unchanged toast, get column name and value from old record
                                coalesce((c).name, (oc).name),
                                case
                                    when (c).name is null then (oc).value
                                    else (c).value
                                end
                            )
                        from
                            unnest(columns) c
                            full outer join unnest(old_columns) oc
                                on (c).name = (oc).name
                        where
                            coalesce((c).is_selectable, (oc).is_selectable)
                            and ( not error_record_exceeds_max_size or (octet_length((c).value::text) <= 64))
                    )
                )
            else '{}'::jsonb
        end
        -- Add "old_record" key for update and delete
        || case
            when action = 'UPDATE' then
                jsonb_build_object(
                        'old_record',
                        (
                            select jsonb_object_agg((c).name, (c).value)
                            from unnest(old_columns) c
                            where
                                (c).is_selectable
                                and ( not error_record_exceeds_max_size or (octet_length((c).value::text) <= 64))
                        )
                    )
            when action = 'DELETE' then
                jsonb_build_object(
                    'old_record',
                    (
                        select jsonb_object_agg((c).name, (c).value)
                        from unnest(old_columns) c
                        where
                            (c).is_selectable
                            and ( not error_record_exceeds_max_size or (octet_length((c).value::text) <= 64))
                            and ( not is_rls_enabled or (c).is_pkey ) -- if RLS enabled, we can't secure deletes so filter to pkey
                    )
                )
            else '{}'::jsonb
        end;

        -- Create the prepared statement
        if is_rls_enabled and action <> 'DELETE' then
            if (select 1 from pg_prepared_statements where name = 'walrus_rls_stmt' limit 1) > 0 then
                deallocate walrus_rls_stmt;
            end if;
            execute realtime.build_prepared_statement_sql('walrus_rls_stmt', entity_, columns);
        end if;

        visible_to_subscription_ids = '{}';

        for subscription_id, claims in (
                select
                    subs.subscription_id,
                    subs.claims
                from
                    unnest(subscriptions) subs
                where
                    subs.entity = entity_
                    and subs.claims_role = working_role
                    and (
                        realtime.is_visible_through_filters(columns, subs.filters)
                        or (
                          action = 'DELETE'
                          and realtime.is_visible_through_filters(old_columns, subs.filters)
                        )
                    )
        ) loop

            if not is_rls_enabled or action = 'DELETE' then
                visible_to_subscription_ids = visible_to_subscription_ids || subscription_id;
            else
                -- Check if RLS allows the role to see the record
                perform
                    -- Trim leading and trailing quotes from working_role because set_config
                    -- doesn't recognize the role as valid if they are included
                    set_config('role', trim(both '"' from working_role::text), true),
                    set_config('request.jwt.claims', claims::text, true);

                execute 'execute walrus_rls_stmt' into subscription_has_access;

                if subscription_has_access then
                    visible_to_subscription_ids = visible_to_subscription_ids || subscription_id;
                end if;
            end if;
        end loop;

        perform set_config('role', null, true);

        return next (
            output,
            is_rls_enabled,
            visible_to_subscription_ids,
            case
                when error_record_exceeds_max_size then array['Error 413: Payload Too Large']
                else '{}'
            end
        )::realtime.wal_rls;

    end if;
end loop;

perform set_config('role', null, true);
end;
$$;


--
-- Name: broadcast_changes(text, text, text, text, text, record, record, text); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.broadcast_changes(topic_name text, event_name text, operation text, table_name text, table_schema text, new record, old record, level text DEFAULT 'ROW'::text) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
    -- Declare a variable to hold the JSONB representation of the row
    row_data jsonb := '{}'::jsonb;
BEGIN
    IF level = 'STATEMENT' THEN
        RAISE EXCEPTION 'function can only be triggered for each row, not for each statement';
    END IF;
    -- Check the operation type and handle accordingly
    IF operation = 'INSERT' OR operation = 'UPDATE' OR operation = 'DELETE' THEN
        row_data := jsonb_build_object('old_record', OLD, 'record', NEW, 'operation', operation, 'table', table_name, 'schema', table_schema);
        PERFORM realtime.send (row_data, event_name, topic_name);
    ELSE
        RAISE EXCEPTION 'Unexpected operation type: %', operation;
    END IF;
EXCEPTION
    WHEN OTHERS THEN
        RAISE EXCEPTION 'Failed to process the row: %', SQLERRM;
END;

$$;


--
-- Name: build_prepared_statement_sql(text, regclass, realtime.wal_column[]); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.build_prepared_statement_sql(prepared_statement_name text, entity regclass, columns realtime.wal_column[]) RETURNS text
    LANGUAGE sql
    AS $$
      /*
      Builds a sql string that, if executed, creates a prepared statement to
      tests retrive a row from *entity* by its primary key columns.
      Example
          select realtime.build_prepared_statement_sql('public.notes', '{"id"}'::text[], '{"bigint"}'::text[])
      */
          select
      'prepare ' || prepared_statement_name || ' as
          select
              exists(
                  select
                      1
                  from
                      ' || entity || '
                  where
                      ' || string_agg(quote_ident(pkc.name) || '=' || quote_nullable(pkc.value #>> '{}') , ' and ') || '
              )'
          from
              unnest(columns) pkc
          where
              pkc.is_pkey
          group by
              entity
      $$;


--
-- Name: cast(text, regtype); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime."cast"(val text, type_ regtype) RETURNS jsonb
    LANGUAGE plpgsql IMMUTABLE
    AS $$
    declare
      res jsonb;
    begin
      execute format('select to_jsonb(%L::'|| type_::text || ')', val)  into res;
      return res;
    end
    $$;


--
-- Name: check_equality_op(realtime.equality_op, regtype, text, text); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.check_equality_op(op realtime.equality_op, type_ regtype, val_1 text, val_2 text) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
      /*
      Casts *val_1* and *val_2* as type *type_* and check the *op* condition for truthiness
      */
      declare
          op_symbol text = (
              case
                  when op = 'eq' then '='
                  when op = 'neq' then '!='
                  when op = 'lt' then '<'
                  when op = 'lte' then '<='
                  when op = 'gt' then '>'
                  when op = 'gte' then '>='
                  when op = 'in' then '= any'
                  else 'UNKNOWN OP'
              end
          );
          res boolean;
      begin
          execute format(
              'select %L::'|| type_::text || ' ' || op_symbol
              || ' ( %L::'
              || (
                  case
                      when op = 'in' then type_::text || '[]'
                      else type_::text end
              )
              || ')', val_1, val_2) into res;
          return res;
      end;
      $$;


--
-- Name: is_visible_through_filters(realtime.wal_column[], realtime.user_defined_filter[]); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.is_visible_through_filters(columns realtime.wal_column[], filters realtime.user_defined_filter[]) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    AS $_$
    /*
    Should the record be visible (true) or filtered out (false) after *filters* are applied
    */
        select
            -- Default to allowed when no filters present
            $2 is null -- no filters. this should not happen because subscriptions has a default
            or array_length($2, 1) is null -- array length of an empty array is null
            or bool_and(
                coalesce(
                    realtime.check_equality_op(
                        op:=f.op,
                        type_:=coalesce(
                            col.type_oid::regtype, -- null when wal2json version <= 2.4
                            col.type_name::regtype
                        ),
                        -- cast jsonb to text
                        val_1:=col.value #>> '{}',
                        val_2:=f.value
                    ),
                    false -- if null, filter does not match
                )
            )
        from
            unnest(filters) f
            join unnest(columns) col
                on f.column_name = col.name;
    $_$;


--
-- Name: list_changes(name, name, integer, integer); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.list_changes(publication name, slot_name name, max_changes integer, max_record_bytes integer) RETURNS SETOF realtime.wal_rls
    LANGUAGE sql
    SET log_min_messages TO 'fatal'
    AS $$
      with pub as (
        select
          concat_ws(
            ',',
            case when bool_or(pubinsert) then 'insert' else null end,
            case when bool_or(pubupdate) then 'update' else null end,
            case when bool_or(pubdelete) then 'delete' else null end
          ) as w2j_actions,
          coalesce(
            string_agg(
              realtime.quote_wal2json(format('%I.%I', schemaname, tablename)::regclass),
              ','
            ) filter (where ppt.tablename is not null and ppt.tablename not like '% %'),
            ''
          ) w2j_add_tables
        from
          pg_publication pp
          left join pg_publication_tables ppt
            on pp.pubname = ppt.pubname
        where
          pp.pubname = publication
        group by
          pp.pubname
        limit 1
      ),
      w2j as (
        select
          x.*, pub.w2j_add_tables
        from
          pub,
          pg_logical_slot_get_changes(
            slot_name, null, max_changes,
            'include-pk', 'true',
            'include-transaction', 'false',
            'include-timestamp', 'true',
            'include-type-oids', 'true',
            'format-version', '2',
            'actions', pub.w2j_actions,
            'add-tables', pub.w2j_add_tables
          ) x
      )
      select
        xyz.wal,
        xyz.is_rls_enabled,
        xyz.subscription_ids,
        xyz.errors
      from
        w2j,
        realtime.apply_rls(
          wal := w2j.data::jsonb,
          max_record_bytes := max_record_bytes
        ) xyz(wal, is_rls_enabled, subscription_ids, errors)
      where
        w2j.w2j_add_tables <> ''
        and xyz.subscription_ids[1] is not null
    $$;


--
-- Name: quote_wal2json(regclass); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.quote_wal2json(entity regclass) RETURNS text
    LANGUAGE sql IMMUTABLE STRICT
    AS $$
      select
        (
          select string_agg('' || ch,'')
          from unnest(string_to_array(nsp.nspname::text, null)) with ordinality x(ch, idx)
          where
            not (x.idx = 1 and x.ch = '"')
            and not (
              x.idx = array_length(string_to_array(nsp.nspname::text, null), 1)
              and x.ch = '"'
            )
        )
        || '.'
        || (
          select string_agg('' || ch,'')
          from unnest(string_to_array(pc.relname::text, null)) with ordinality x(ch, idx)
          where
            not (x.idx = 1 and x.ch = '"')
            and not (
              x.idx = array_length(string_to_array(nsp.nspname::text, null), 1)
              and x.ch = '"'
            )
          )
      from
        pg_class pc
        join pg_namespace nsp
          on pc.relnamespace = nsp.oid
      where
        pc.oid = entity
    $$;


--
-- Name: send(jsonb, text, text, boolean); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.send(payload jsonb, event text, topic text, private boolean DEFAULT true) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
  generated_id uuid;
  final_payload jsonb;
BEGIN
  BEGIN
    -- Generate a new UUID for the id
    generated_id := gen_random_uuid();

    -- Check if payload has an 'id' key, if not, add the generated UUID
    IF payload ? 'id' THEN
      final_payload := payload;
    ELSE
      final_payload := jsonb_set(payload, '{id}', to_jsonb(generated_id));
    END IF;

    -- Set the topic configuration
    EXECUTE format('SET LOCAL realtime.topic TO %L', topic);

    -- Attempt to insert the message
    INSERT INTO realtime.messages (id, payload, event, topic, private, extension)
    VALUES (generated_id, final_payload, event, topic, private, 'broadcast');
  EXCEPTION
    WHEN OTHERS THEN
      -- Capture and notify the error
      RAISE WARNING 'ErrorSendingBroadcastMessage: %', SQLERRM;
  END;
END;
$$;


--
-- Name: subscription_check_filters(); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.subscription_check_filters() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    /*
    Validates that the user defined filters for a subscription:
    - refer to valid columns that the claimed role may access
    - values are coercable to the correct column type
    */
    declare
        col_names text[] = coalesce(
                array_agg(c.column_name order by c.ordinal_position),
                '{}'::text[]
            )
            from
                information_schema.columns c
            where
                format('%I.%I', c.table_schema, c.table_name)::regclass = new.entity
                and pg_catalog.has_column_privilege(
                    (new.claims ->> 'role'),
                    format('%I.%I', c.table_schema, c.table_name)::regclass,
                    c.column_name,
                    'SELECT'
                );
        filter realtime.user_defined_filter;
        col_type regtype;

        in_val jsonb;
    begin
        for filter in select * from unnest(new.filters) loop
            -- Filtered column is valid
            if not filter.column_name = any(col_names) then
                raise exception 'invalid column for filter %', filter.column_name;
            end if;

            -- Type is sanitized and safe for string interpolation
            col_type = (
                select atttypid::regtype
                from pg_catalog.pg_attribute
                where attrelid = new.entity
                      and attname = filter.column_name
            );
            if col_type is null then
                raise exception 'failed to lookup type for column %', filter.column_name;
            end if;

            -- Set maximum number of entries for in filter
            if filter.op = 'in'::realtime.equality_op then
                in_val = realtime.cast(filter.value, (col_type::text || '[]')::regtype);
                if coalesce(jsonb_array_length(in_val), 0) > 100 then
                    raise exception 'too many values for `in` filter. Maximum 100';
                end if;
            else
                -- raises an exception if value is not coercable to type
                perform realtime.cast(filter.value, col_type);
            end if;

        end loop;

        -- Apply consistent order to filters so the unique constraint on
        -- (subscription_id, entity, filters) can't be tricked by a different filter order
        new.filters = coalesce(
            array_agg(f order by f.column_name, f.op, f.value),
            '{}'
        ) from unnest(new.filters) f;

        return new;
    end;
    $$;


--
-- Name: to_regrole(text); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.to_regrole(role_name text) RETURNS regrole
    LANGUAGE sql IMMUTABLE
    AS $$ select role_name::regrole $$;


--
-- Name: topic(); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.topic() RETURNS text
    LANGUAGE sql STABLE
    AS $$
select nullif(current_setting('realtime.topic', true), '')::text;
$$;


--
-- Name: can_insert_object(text, text, uuid, jsonb); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.can_insert_object(bucketid text, name text, owner uuid, metadata jsonb) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
  INSERT INTO "storage"."objects" ("bucket_id", "name", "owner", "metadata") VALUES (bucketid, name, owner, metadata);
  -- hack to rollback the successful insert
  RAISE sqlstate 'PT200' using
  message = 'ROLLBACK',
  detail = 'rollback successful insert';
END
$$;


--
-- Name: delete_leaf_prefixes(text[], text[]); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.delete_leaf_prefixes(bucket_ids text[], names text[]) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    AS $$
DECLARE
    v_rows_deleted integer;
BEGIN
    LOOP
        WITH candidates AS (
            SELECT DISTINCT
                t.bucket_id,
                unnest(storage.get_prefixes(t.name)) AS name
            FROM unnest(bucket_ids, names) AS t(bucket_id, name)
        ),
        uniq AS (
             SELECT
                 bucket_id,
                 name,
                 storage.get_level(name) AS level
             FROM candidates
             WHERE name <> ''
             GROUP BY bucket_id, name
        ),
        leaf AS (
             SELECT
                 p.bucket_id,
                 p.name,
                 p.level
             FROM storage.prefixes AS p
                  JOIN uniq AS u
                       ON u.bucket_id = p.bucket_id
                           AND u.name = p.name
                           AND u.level = p.level
             WHERE NOT EXISTS (
                 SELECT 1
                 FROM storage.objects AS o
                 WHERE o.bucket_id = p.bucket_id
                   AND o.level = p.level + 1
                   AND o.name COLLATE "C" LIKE p.name || '/%'
             )
             AND NOT EXISTS (
                 SELECT 1
                 FROM storage.prefixes AS c
                 WHERE c.bucket_id = p.bucket_id
                   AND c.level = p.level + 1
                   AND c.name COLLATE "C" LIKE p.name || '/%'
             )
        )
        DELETE
        FROM storage.prefixes AS p
            USING leaf AS l
        WHERE p.bucket_id = l.bucket_id
          AND p.name = l.name
          AND p.level = l.level;

        GET DIAGNOSTICS v_rows_deleted = ROW_COUNT;
        EXIT WHEN v_rows_deleted = 0;
    END LOOP;
END;
$$;


--
-- Name: enforce_bucket_name_length(); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.enforce_bucket_name_length() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    if length(new.name) > 100 then
        raise exception 'bucket name "%" is too long (% characters). Max is 100.', new.name, length(new.name);
    end if;
    return new;
end;
$$;


--
-- Name: extension(text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.extension(name text) RETURNS text
    LANGUAGE plpgsql IMMUTABLE
    AS $$
DECLARE
    _parts text[];
    _filename text;
BEGIN
    SELECT string_to_array(name, '/') INTO _parts;
    SELECT _parts[array_length(_parts,1)] INTO _filename;
    RETURN reverse(split_part(reverse(_filename), '.', 1));
END
$$;


--
-- Name: filename(text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.filename(name text) RETURNS text
    LANGUAGE plpgsql
    AS $$
DECLARE
_parts text[];
BEGIN
	select string_to_array(name, '/') into _parts;
	return _parts[array_length(_parts,1)];
END
$$;


--
-- Name: foldername(text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.foldername(name text) RETURNS text[]
    LANGUAGE plpgsql IMMUTABLE
    AS $$
DECLARE
    _parts text[];
BEGIN
    -- Split on "/" to get path segments
    SELECT string_to_array(name, '/') INTO _parts;
    -- Return everything except the last segment
    RETURN _parts[1 : array_length(_parts,1) - 1];
END
$$;


--
-- Name: get_common_prefix(text, text, text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.get_common_prefix(p_key text, p_prefix text, p_delimiter text) RETURNS text
    LANGUAGE sql IMMUTABLE
    AS $$
SELECT CASE
    WHEN position(p_delimiter IN substring(p_key FROM length(p_prefix) + 1)) > 0
    THEN left(p_key, length(p_prefix) + position(p_delimiter IN substring(p_key FROM length(p_prefix) + 1)))
    ELSE NULL
END;
$$;


--
-- Name: get_level(text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.get_level(name text) RETURNS integer
    LANGUAGE sql IMMUTABLE STRICT
    AS $$
SELECT array_length(string_to_array("name", '/'), 1);
$$;


--
-- Name: get_prefix(text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.get_prefix(name text) RETURNS text
    LANGUAGE sql IMMUTABLE STRICT
    AS $_$
SELECT
    CASE WHEN strpos("name", '/') > 0 THEN
             regexp_replace("name", '[\/]{1}[^\/]+\/?$', '')
         ELSE
             ''
        END;
$_$;


--
-- Name: get_prefixes(text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.get_prefixes(name text) RETURNS text[]
    LANGUAGE plpgsql IMMUTABLE STRICT
    AS $$
DECLARE
    parts text[];
    prefixes text[];
    prefix text;
BEGIN
    -- Split the name into parts by '/'
    parts := string_to_array("name", '/');
    prefixes := '{}';

    -- Construct the prefixes, stopping one level below the last part
    FOR i IN 1..array_length(parts, 1) - 1 LOOP
            prefix := array_to_string(parts[1:i], '/');
            prefixes := array_append(prefixes, prefix);
    END LOOP;

    RETURN prefixes;
END;
$$;


--
-- Name: get_size_by_bucket(); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.get_size_by_bucket() RETURNS TABLE(size bigint, bucket_id text)
    LANGUAGE plpgsql STABLE
    AS $$
BEGIN
    return query
        select sum((metadata->>'size')::bigint) as size, obj.bucket_id
        from "storage".objects as obj
        group by obj.bucket_id;
END
$$;


--
-- Name: list_multipart_uploads_with_delimiter(text, text, text, integer, text, text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.list_multipart_uploads_with_delimiter(bucket_id text, prefix_param text, delimiter_param text, max_keys integer DEFAULT 100, next_key_token text DEFAULT ''::text, next_upload_token text DEFAULT ''::text) RETURNS TABLE(key text, id text, created_at timestamp with time zone)
    LANGUAGE plpgsql
    AS $_$
BEGIN
    RETURN QUERY EXECUTE
        'SELECT DISTINCT ON(key COLLATE "C") * from (
            SELECT
                CASE
                    WHEN position($2 IN substring(key from length($1) + 1)) > 0 THEN
                        substring(key from 1 for length($1) + position($2 IN substring(key from length($1) + 1)))
                    ELSE
                        key
                END AS key, id, created_at
            FROM
                storage.s3_multipart_uploads
            WHERE
                bucket_id = $5 AND
                key ILIKE $1 || ''%'' AND
                CASE
                    WHEN $4 != '''' AND $6 = '''' THEN
                        CASE
                            WHEN position($2 IN substring(key from length($1) + 1)) > 0 THEN
                                substring(key from 1 for length($1) + position($2 IN substring(key from length($1) + 1))) COLLATE "C" > $4
                            ELSE
                                key COLLATE "C" > $4
                            END
                    ELSE
                        true
                END AND
                CASE
                    WHEN $6 != '''' THEN
                        id COLLATE "C" > $6
                    ELSE
                        true
                    END
            ORDER BY
                key COLLATE "C" ASC, created_at ASC) as e order by key COLLATE "C" LIMIT $3'
        USING prefix_param, delimiter_param, max_keys, next_key_token, bucket_id, next_upload_token;
END;
$_$;


--
-- Name: list_objects_with_delimiter(text, text, text, integer, text, text, text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.list_objects_with_delimiter(_bucket_id text, prefix_param text, delimiter_param text, max_keys integer DEFAULT 100, start_after text DEFAULT ''::text, next_token text DEFAULT ''::text, sort_order text DEFAULT 'asc'::text) RETURNS TABLE(name text, id uuid, metadata jsonb, updated_at timestamp with time zone, created_at timestamp with time zone, last_accessed_at timestamp with time zone)
    LANGUAGE plpgsql STABLE
    AS $_$
DECLARE
    v_peek_name TEXT;
    v_current RECORD;
    v_common_prefix TEXT;

    -- Configuration
    v_is_asc BOOLEAN;
    v_prefix TEXT;
    v_start TEXT;
    v_upper_bound TEXT;
    v_file_batch_size INT;

    -- Seek state
    v_next_seek TEXT;
    v_count INT := 0;

    -- Dynamic SQL for batch query only
    v_batch_query TEXT;

BEGIN
    -- ========================================================================
    -- INITIALIZATION
    -- ========================================================================
    v_is_asc := lower(coalesce(sort_order, 'asc')) = 'asc';
    v_prefix := coalesce(prefix_param, '');
    v_start := CASE WHEN coalesce(next_token, '') <> '' THEN next_token ELSE coalesce(start_after, '') END;
    v_file_batch_size := LEAST(GREATEST(max_keys * 2, 100), 1000);

    -- Calculate upper bound for prefix filtering (bytewise, using COLLATE "C")
    IF v_prefix = '' THEN
        v_upper_bound := NULL;
    ELSIF right(v_prefix, 1) = delimiter_param THEN
        v_upper_bound := left(v_prefix, -1) || chr(ascii(delimiter_param) + 1);
    ELSE
        v_upper_bound := left(v_prefix, -1) || chr(ascii(right(v_prefix, 1)) + 1);
    END IF;

    -- Build batch query (dynamic SQL - called infrequently, amortized over many rows)
    IF v_is_asc THEN
        IF v_upper_bound IS NOT NULL THEN
            v_batch_query := 'SELECT o.name, o.id, o.updated_at, o.created_at, o.last_accessed_at, o.metadata ' ||
                'FROM storage.objects o WHERE o.bucket_id = $1 AND o.name COLLATE "C" >= $2 ' ||
                'AND o.name COLLATE "C" < $3 ORDER BY o.name COLLATE "C" ASC LIMIT $4';
        ELSE
            v_batch_query := 'SELECT o.name, o.id, o.updated_at, o.created_at, o.last_accessed_at, o.metadata ' ||
                'FROM storage.objects o WHERE o.bucket_id = $1 AND o.name COLLATE "C" >= $2 ' ||
                'ORDER BY o.name COLLATE "C" ASC LIMIT $4';
        END IF;
    ELSE
        IF v_upper_bound IS NOT NULL THEN
            v_batch_query := 'SELECT o.name, o.id, o.updated_at, o.created_at, o.last_accessed_at, o.metadata ' ||
                'FROM storage.objects o WHERE o.bucket_id = $1 AND o.name COLLATE "C" < $2 ' ||
                'AND o.name COLLATE "C" >= $3 ORDER BY o.name COLLATE "C" DESC LIMIT $4';
        ELSE
            v_batch_query := 'SELECT o.name, o.id, o.updated_at, o.created_at, o.last_accessed_at, o.metadata ' ||
                'FROM storage.objects o WHERE o.bucket_id = $1 AND o.name COLLATE "C" < $2 ' ||
                'ORDER BY o.name COLLATE "C" DESC LIMIT $4';
        END IF;
    END IF;

    -- ========================================================================
    -- SEEK INITIALIZATION: Determine starting position
    -- ========================================================================
    IF v_start = '' THEN
        IF v_is_asc THEN
            v_next_seek := v_prefix;
        ELSE
            -- DESC without cursor: find the last item in range
            IF v_upper_bound IS NOT NULL THEN
                SELECT o.name INTO v_next_seek FROM storage.objects o
                WHERE o.bucket_id = _bucket_id AND o.name COLLATE "C" >= v_prefix AND o.name COLLATE "C" < v_upper_bound
                ORDER BY o.name COLLATE "C" DESC LIMIT 1;
            ELSIF v_prefix <> '' THEN
                SELECT o.name INTO v_next_seek FROM storage.objects o
                WHERE o.bucket_id = _bucket_id AND o.name COLLATE "C" >= v_prefix
                ORDER BY o.name COLLATE "C" DESC LIMIT 1;
            ELSE
                SELECT o.name INTO v_next_seek FROM storage.objects o
                WHERE o.bucket_id = _bucket_id
                ORDER BY o.name COLLATE "C" DESC LIMIT 1;
            END IF;

            IF v_next_seek IS NOT NULL THEN
                v_next_seek := v_next_seek || delimiter_param;
            ELSE
                RETURN;
            END IF;
        END IF;
    ELSE
        -- Cursor provided: determine if it refers to a folder or leaf
        IF EXISTS (
            SELECT 1 FROM storage.objects o
            WHERE o.bucket_id = _bucket_id
              AND o.name COLLATE "C" LIKE v_start || delimiter_param || '%'
            LIMIT 1
        ) THEN
            -- Cursor refers to a folder
            IF v_is_asc THEN
                v_next_seek := v_start || chr(ascii(delimiter_param) + 1);
            ELSE
                v_next_seek := v_start || delimiter_param;
            END IF;
        ELSE
            -- Cursor refers to a leaf object
            IF v_is_asc THEN
                v_next_seek := v_start || delimiter_param;
            ELSE
                v_next_seek := v_start;
            END IF;
        END IF;
    END IF;

    -- ========================================================================
    -- MAIN LOOP: Hybrid peek-then-batch algorithm
    -- Uses STATIC SQL for peek (hot path) and DYNAMIC SQL for batch
    -- ========================================================================
    LOOP
        EXIT WHEN v_count >= max_keys;

        -- STEP 1: PEEK using STATIC SQL (plan cached, very fast)
        IF v_is_asc THEN
            IF v_upper_bound IS NOT NULL THEN
                SELECT o.name INTO v_peek_name FROM storage.objects o
                WHERE o.bucket_id = _bucket_id AND o.name COLLATE "C" >= v_next_seek AND o.name COLLATE "C" < v_upper_bound
                ORDER BY o.name COLLATE "C" ASC LIMIT 1;
            ELSE
                SELECT o.name INTO v_peek_name FROM storage.objects o
                WHERE o.bucket_id = _bucket_id AND o.name COLLATE "C" >= v_next_seek
                ORDER BY o.name COLLATE "C" ASC LIMIT 1;
            END IF;
        ELSE
            IF v_upper_bound IS NOT NULL THEN
                SELECT o.name INTO v_peek_name FROM storage.objects o
                WHERE o.bucket_id = _bucket_id AND o.name COLLATE "C" < v_next_seek AND o.name COLLATE "C" >= v_prefix
                ORDER BY o.name COLLATE "C" DESC LIMIT 1;
            ELSIF v_prefix <> '' THEN
                SELECT o.name INTO v_peek_name FROM storage.objects o
                WHERE o.bucket_id = _bucket_id AND o.name COLLATE "C" < v_next_seek AND o.name COLLATE "C" >= v_prefix
                ORDER BY o.name COLLATE "C" DESC LIMIT 1;
            ELSE
                SELECT o.name INTO v_peek_name FROM storage.objects o
                WHERE o.bucket_id = _bucket_id AND o.name COLLATE "C" < v_next_seek
                ORDER BY o.name COLLATE "C" DESC LIMIT 1;
            END IF;
        END IF;

        EXIT WHEN v_peek_name IS NULL;

        -- STEP 2: Check if this is a FOLDER or FILE
        v_common_prefix := storage.get_common_prefix(v_peek_name, v_prefix, delimiter_param);

        IF v_common_prefix IS NOT NULL THEN
            -- FOLDER: Emit and skip to next folder (no heap access needed)
            name := rtrim(v_common_prefix, delimiter_param);
            id := NULL;
            updated_at := NULL;
            created_at := NULL;
            last_accessed_at := NULL;
            metadata := NULL;
            RETURN NEXT;
            v_count := v_count + 1;

            -- Advance seek past the folder range
            IF v_is_asc THEN
                v_next_seek := left(v_common_prefix, -1) || chr(ascii(delimiter_param) + 1);
            ELSE
                v_next_seek := v_common_prefix;
            END IF;
        ELSE
            -- FILE: Batch fetch using DYNAMIC SQL (overhead amortized over many rows)
            -- For ASC: upper_bound is the exclusive upper limit (< condition)
            -- For DESC: prefix is the inclusive lower limit (>= condition)
            FOR v_current IN EXECUTE v_batch_query USING _bucket_id, v_next_seek,
                CASE WHEN v_is_asc THEN COALESCE(v_upper_bound, v_prefix) ELSE v_prefix END, v_file_batch_size
            LOOP
                v_common_prefix := storage.get_common_prefix(v_current.name, v_prefix, delimiter_param);

                IF v_common_prefix IS NOT NULL THEN
                    -- Hit a folder: exit batch, let peek handle it
                    v_next_seek := v_current.name;
                    EXIT;
                END IF;

                -- Emit file
                name := v_current.name;
                id := v_current.id;
                updated_at := v_current.updated_at;
                created_at := v_current.created_at;
                last_accessed_at := v_current.last_accessed_at;
                metadata := v_current.metadata;
                RETURN NEXT;
                v_count := v_count + 1;

                -- Advance seek past this file
                IF v_is_asc THEN
                    v_next_seek := v_current.name || delimiter_param;
                ELSE
                    v_next_seek := v_current.name;
                END IF;

                EXIT WHEN v_count >= max_keys;
            END LOOP;
        END IF;
    END LOOP;
END;
$_$;


--
-- Name: operation(); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.operation() RETURNS text
    LANGUAGE plpgsql STABLE
    AS $$
BEGIN
    RETURN current_setting('storage.operation', true);
END;
$$;


--
-- Name: protect_delete(); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.protect_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Check if storage.allow_delete_query is set to 'true'
    IF COALESCE(current_setting('storage.allow_delete_query', true), 'false') != 'true' THEN
        RAISE EXCEPTION 'Direct deletion from storage tables is not allowed. Use the Storage API instead.'
            USING HINT = 'This prevents accidental data loss from orphaned objects.',
                  ERRCODE = '42501';
    END IF;
    RETURN NULL;
END;
$$;


--
-- Name: search(text, text, integer, integer, integer, text, text, text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.search(prefix text, bucketname text, limits integer DEFAULT 100, levels integer DEFAULT 1, offsets integer DEFAULT 0, search text DEFAULT ''::text, sortcolumn text DEFAULT 'name'::text, sortorder text DEFAULT 'asc'::text) RETURNS TABLE(name text, id uuid, updated_at timestamp with time zone, created_at timestamp with time zone, last_accessed_at timestamp with time zone, metadata jsonb)
    LANGUAGE plpgsql STABLE
    AS $_$
DECLARE
    v_peek_name TEXT;
    v_current RECORD;
    v_common_prefix TEXT;
    v_delimiter CONSTANT TEXT := '/';

    -- Configuration
    v_limit INT;
    v_prefix TEXT;
    v_prefix_lower TEXT;
    v_is_asc BOOLEAN;
    v_order_by TEXT;
    v_sort_order TEXT;
    v_upper_bound TEXT;
    v_file_batch_size INT;

    -- Dynamic SQL for batch query only
    v_batch_query TEXT;

    -- Seek state
    v_next_seek TEXT;
    v_count INT := 0;
    v_skipped INT := 0;
BEGIN
    -- ========================================================================
    -- INITIALIZATION
    -- ========================================================================
    v_limit := LEAST(coalesce(limits, 100), 1500);
    v_prefix := coalesce(prefix, '') || coalesce(search, '');
    v_prefix_lower := lower(v_prefix);
    v_is_asc := lower(coalesce(sortorder, 'asc')) = 'asc';
    v_file_batch_size := LEAST(GREATEST(v_limit * 2, 100), 1000);

    -- Validate sort column
    CASE lower(coalesce(sortcolumn, 'name'))
        WHEN 'name' THEN v_order_by := 'name';
        WHEN 'updated_at' THEN v_order_by := 'updated_at';
        WHEN 'created_at' THEN v_order_by := 'created_at';
        WHEN 'last_accessed_at' THEN v_order_by := 'last_accessed_at';
        ELSE v_order_by := 'name';
    END CASE;

    v_sort_order := CASE WHEN v_is_asc THEN 'asc' ELSE 'desc' END;

    -- ========================================================================
    -- NON-NAME SORTING: Use path_tokens approach (unchanged)
    -- ========================================================================
    IF v_order_by != 'name' THEN
        RETURN QUERY EXECUTE format(
            $sql$
            WITH folders AS (
                SELECT path_tokens[$1] AS folder
                FROM storage.objects
                WHERE objects.name ILIKE $2 || '%%'
                  AND bucket_id = $3
                  AND array_length(objects.path_tokens, 1) <> $1
                GROUP BY folder
                ORDER BY folder %s
            )
            (SELECT folder AS "name",
                   NULL::uuid AS id,
                   NULL::timestamptz AS updated_at,
                   NULL::timestamptz AS created_at,
                   NULL::timestamptz AS last_accessed_at,
                   NULL::jsonb AS metadata FROM folders)
            UNION ALL
            (SELECT path_tokens[$1] AS "name",
                   id, updated_at, created_at, last_accessed_at, metadata
             FROM storage.objects
             WHERE objects.name ILIKE $2 || '%%'
               AND bucket_id = $3
               AND array_length(objects.path_tokens, 1) = $1
             ORDER BY %I %s)
            LIMIT $4 OFFSET $5
            $sql$, v_sort_order, v_order_by, v_sort_order
        ) USING levels, v_prefix, bucketname, v_limit, offsets;
        RETURN;
    END IF;

    -- ========================================================================
    -- NAME SORTING: Hybrid skip-scan with batch optimization
    -- ========================================================================

    -- Calculate upper bound for prefix filtering
    IF v_prefix_lower = '' THEN
        v_upper_bound := NULL;
    ELSIF right(v_prefix_lower, 1) = v_delimiter THEN
        v_upper_bound := left(v_prefix_lower, -1) || chr(ascii(v_delimiter) + 1);
    ELSE
        v_upper_bound := left(v_prefix_lower, -1) || chr(ascii(right(v_prefix_lower, 1)) + 1);
    END IF;

    -- Build batch query (dynamic SQL - called infrequently, amortized over many rows)
    IF v_is_asc THEN
        IF v_upper_bound IS NOT NULL THEN
            v_batch_query := 'SELECT o.name, o.id, o.updated_at, o.created_at, o.last_accessed_at, o.metadata ' ||
                'FROM storage.objects o WHERE o.bucket_id = $1 AND lower(o.name) COLLATE "C" >= $2 ' ||
                'AND lower(o.name) COLLATE "C" < $3 ORDER BY lower(o.name) COLLATE "C" ASC LIMIT $4';
        ELSE
            v_batch_query := 'SELECT o.name, o.id, o.updated_at, o.created_at, o.last_accessed_at, o.metadata ' ||
                'FROM storage.objects o WHERE o.bucket_id = $1 AND lower(o.name) COLLATE "C" >= $2 ' ||
                'ORDER BY lower(o.name) COLLATE "C" ASC LIMIT $4';
        END IF;
    ELSE
        IF v_upper_bound IS NOT NULL THEN
            v_batch_query := 'SELECT o.name, o.id, o.updated_at, o.created_at, o.last_accessed_at, o.metadata ' ||
                'FROM storage.objects o WHERE o.bucket_id = $1 AND lower(o.name) COLLATE "C" < $2 ' ||
                'AND lower(o.name) COLLATE "C" >= $3 ORDER BY lower(o.name) COLLATE "C" DESC LIMIT $4';
        ELSE
            v_batch_query := 'SELECT o.name, o.id, o.updated_at, o.created_at, o.last_accessed_at, o.metadata ' ||
                'FROM storage.objects o WHERE o.bucket_id = $1 AND lower(o.name) COLLATE "C" < $2 ' ||
                'ORDER BY lower(o.name) COLLATE "C" DESC LIMIT $4';
        END IF;
    END IF;

    -- Initialize seek position
    IF v_is_asc THEN
        v_next_seek := v_prefix_lower;
    ELSE
        -- DESC: find the last item in range first (static SQL)
        IF v_upper_bound IS NOT NULL THEN
            SELECT o.name INTO v_peek_name FROM storage.objects o
            WHERE o.bucket_id = bucketname AND lower(o.name) COLLATE "C" >= v_prefix_lower AND lower(o.name) COLLATE "C" < v_upper_bound
            ORDER BY lower(o.name) COLLATE "C" DESC LIMIT 1;
        ELSIF v_prefix_lower <> '' THEN
            SELECT o.name INTO v_peek_name FROM storage.objects o
            WHERE o.bucket_id = bucketname AND lower(o.name) COLLATE "C" >= v_prefix_lower
            ORDER BY lower(o.name) COLLATE "C" DESC LIMIT 1;
        ELSE
            SELECT o.name INTO v_peek_name FROM storage.objects o
            WHERE o.bucket_id = bucketname
            ORDER BY lower(o.name) COLLATE "C" DESC LIMIT 1;
        END IF;

        IF v_peek_name IS NOT NULL THEN
            v_next_seek := lower(v_peek_name) || v_delimiter;
        ELSE
            RETURN;
        END IF;
    END IF;

    -- ========================================================================
    -- MAIN LOOP: Hybrid peek-then-batch algorithm
    -- Uses STATIC SQL for peek (hot path) and DYNAMIC SQL for batch
    -- ========================================================================
    LOOP
        EXIT WHEN v_count >= v_limit;

        -- STEP 1: PEEK using STATIC SQL (plan cached, very fast)
        IF v_is_asc THEN
            IF v_upper_bound IS NOT NULL THEN
                SELECT o.name INTO v_peek_name FROM storage.objects o
                WHERE o.bucket_id = bucketname AND lower(o.name) COLLATE "C" >= v_next_seek AND lower(o.name) COLLATE "C" < v_upper_bound
                ORDER BY lower(o.name) COLLATE "C" ASC LIMIT 1;
            ELSE
                SELECT o.name INTO v_peek_name FROM storage.objects o
                WHERE o.bucket_id = bucketname AND lower(o.name) COLLATE "C" >= v_next_seek
                ORDER BY lower(o.name) COLLATE "C" ASC LIMIT 1;
            END IF;
        ELSE
            IF v_upper_bound IS NOT NULL THEN
                SELECT o.name INTO v_peek_name FROM storage.objects o
                WHERE o.bucket_id = bucketname AND lower(o.name) COLLATE "C" < v_next_seek AND lower(o.name) COLLATE "C" >= v_prefix_lower
                ORDER BY lower(o.name) COLLATE "C" DESC LIMIT 1;
            ELSIF v_prefix_lower <> '' THEN
                SELECT o.name INTO v_peek_name FROM storage.objects o
                WHERE o.bucket_id = bucketname AND lower(o.name) COLLATE "C" < v_next_seek AND lower(o.name) COLLATE "C" >= v_prefix_lower
                ORDER BY lower(o.name) COLLATE "C" DESC LIMIT 1;
            ELSE
                SELECT o.name INTO v_peek_name FROM storage.objects o
                WHERE o.bucket_id = bucketname AND lower(o.name) COLLATE "C" < v_next_seek
                ORDER BY lower(o.name) COLLATE "C" DESC LIMIT 1;
            END IF;
        END IF;

        EXIT WHEN v_peek_name IS NULL;

        -- STEP 2: Check if this is a FOLDER or FILE
        v_common_prefix := storage.get_common_prefix(lower(v_peek_name), v_prefix_lower, v_delimiter);

        IF v_common_prefix IS NOT NULL THEN
            -- FOLDER: Handle offset, emit if needed, skip to next folder
            IF v_skipped < offsets THEN
                v_skipped := v_skipped + 1;
            ELSE
                name := split_part(rtrim(storage.get_common_prefix(v_peek_name, v_prefix, v_delimiter), v_delimiter), v_delimiter, levels);
                id := NULL;
                updated_at := NULL;
                created_at := NULL;
                last_accessed_at := NULL;
                metadata := NULL;
                RETURN NEXT;
                v_count := v_count + 1;
            END IF;

            -- Advance seek past the folder range
            IF v_is_asc THEN
                v_next_seek := lower(left(v_common_prefix, -1)) || chr(ascii(v_delimiter) + 1);
            ELSE
                v_next_seek := lower(v_common_prefix);
            END IF;
        ELSE
            -- FILE: Batch fetch using DYNAMIC SQL (overhead amortized over many rows)
            -- For ASC: upper_bound is the exclusive upper limit (< condition)
            -- For DESC: prefix_lower is the inclusive lower limit (>= condition)
            FOR v_current IN EXECUTE v_batch_query
                USING bucketname, v_next_seek,
                    CASE WHEN v_is_asc THEN COALESCE(v_upper_bound, v_prefix_lower) ELSE v_prefix_lower END, v_file_batch_size
            LOOP
                v_common_prefix := storage.get_common_prefix(lower(v_current.name), v_prefix_lower, v_delimiter);

                IF v_common_prefix IS NOT NULL THEN
                    -- Hit a folder: exit batch, let peek handle it
                    v_next_seek := lower(v_current.name);
                    EXIT;
                END IF;

                -- Handle offset skipping
                IF v_skipped < offsets THEN
                    v_skipped := v_skipped + 1;
                ELSE
                    -- Emit file
                    name := split_part(v_current.name, v_delimiter, levels);
                    id := v_current.id;
                    updated_at := v_current.updated_at;
                    created_at := v_current.created_at;
                    last_accessed_at := v_current.last_accessed_at;
                    metadata := v_current.metadata;
                    RETURN NEXT;
                    v_count := v_count + 1;
                END IF;

                -- Advance seek past this file
                IF v_is_asc THEN
                    v_next_seek := lower(v_current.name) || v_delimiter;
                ELSE
                    v_next_seek := lower(v_current.name);
                END IF;

                EXIT WHEN v_count >= v_limit;
            END LOOP;
        END IF;
    END LOOP;
END;
$_$;


--
-- Name: search_by_timestamp(text, text, integer, integer, text, text, text, text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.search_by_timestamp(p_prefix text, p_bucket_id text, p_limit integer, p_level integer, p_start_after text, p_sort_order text, p_sort_column text, p_sort_column_after text) RETURNS TABLE(key text, name text, id uuid, updated_at timestamp with time zone, created_at timestamp with time zone, last_accessed_at timestamp with time zone, metadata jsonb)
    LANGUAGE plpgsql STABLE
    AS $_$
DECLARE
    v_cursor_op text;
    v_query text;
    v_prefix text;
BEGIN
    v_prefix := coalesce(p_prefix, '');

    IF p_sort_order = 'asc' THEN
        v_cursor_op := '>';
    ELSE
        v_cursor_op := '<';
    END IF;

    v_query := format($sql$
        WITH raw_objects AS (
            SELECT
                o.name AS obj_name,
                o.id AS obj_id,
                o.updated_at AS obj_updated_at,
                o.created_at AS obj_created_at,
                o.last_accessed_at AS obj_last_accessed_at,
                o.metadata AS obj_metadata,
                storage.get_common_prefix(o.name, $1, '/') AS common_prefix
            FROM storage.objects o
            WHERE o.bucket_id = $2
              AND o.name COLLATE "C" LIKE $1 || '%%'
        ),
        -- Aggregate common prefixes (folders)
        -- Both created_at and updated_at use MIN(obj_created_at) to match the old prefixes table behavior
        aggregated_prefixes AS (
            SELECT
                rtrim(common_prefix, '/') AS name,
                NULL::uuid AS id,
                MIN(obj_created_at) AS updated_at,
                MIN(obj_created_at) AS created_at,
                NULL::timestamptz AS last_accessed_at,
                NULL::jsonb AS metadata,
                TRUE AS is_prefix
            FROM raw_objects
            WHERE common_prefix IS NOT NULL
            GROUP BY common_prefix
        ),
        leaf_objects AS (
            SELECT
                obj_name AS name,
                obj_id AS id,
                obj_updated_at AS updated_at,
                obj_created_at AS created_at,
                obj_last_accessed_at AS last_accessed_at,
                obj_metadata AS metadata,
                FALSE AS is_prefix
            FROM raw_objects
            WHERE common_prefix IS NULL
        ),
        combined AS (
            SELECT * FROM aggregated_prefixes
            UNION ALL
            SELECT * FROM leaf_objects
        ),
        filtered AS (
            SELECT *
            FROM combined
            WHERE (
                $5 = ''
                OR ROW(
                    date_trunc('milliseconds', %I),
                    name COLLATE "C"
                ) %s ROW(
                    COALESCE(NULLIF($6, '')::timestamptz, 'epoch'::timestamptz),
                    $5
                )
            )
        )
        SELECT
            split_part(name, '/', $3) AS key,
            name,
            id,
            updated_at,
            created_at,
            last_accessed_at,
            metadata
        FROM filtered
        ORDER BY
            COALESCE(date_trunc('milliseconds', %I), 'epoch'::timestamptz) %s,
            name COLLATE "C" %s
        LIMIT $4
    $sql$,
        p_sort_column,
        v_cursor_op,
        p_sort_column,
        p_sort_order,
        p_sort_order
    );

    RETURN QUERY EXECUTE v_query
    USING v_prefix, p_bucket_id, p_level, p_limit, p_start_after, p_sort_column_after;
END;
$_$;


--
-- Name: search_legacy_v1(text, text, integer, integer, integer, text, text, text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.search_legacy_v1(prefix text, bucketname text, limits integer DEFAULT 100, levels integer DEFAULT 1, offsets integer DEFAULT 0, search text DEFAULT ''::text, sortcolumn text DEFAULT 'name'::text, sortorder text DEFAULT 'asc'::text) RETURNS TABLE(name text, id uuid, updated_at timestamp with time zone, created_at timestamp with time zone, last_accessed_at timestamp with time zone, metadata jsonb)
    LANGUAGE plpgsql STABLE
    AS $_$
declare
    v_order_by text;
    v_sort_order text;
begin
    case
        when sortcolumn = 'name' then
            v_order_by = 'name';
        when sortcolumn = 'updated_at' then
            v_order_by = 'updated_at';
        when sortcolumn = 'created_at' then
            v_order_by = 'created_at';
        when sortcolumn = 'last_accessed_at' then
            v_order_by = 'last_accessed_at';
        else
            v_order_by = 'name';
        end case;

    case
        when sortorder = 'asc' then
            v_sort_order = 'asc';
        when sortorder = 'desc' then
            v_sort_order = 'desc';
        else
            v_sort_order = 'asc';
        end case;

    v_order_by = v_order_by || ' ' || v_sort_order;

    return query execute
        'with folders as (
           select path_tokens[$1] as folder
           from storage.objects
             where objects.name ilike $2 || $3 || ''%''
               and bucket_id = $4
               and array_length(objects.path_tokens, 1) <> $1
           group by folder
           order by folder ' || v_sort_order || '
     )
     (select folder as "name",
            null as id,
            null as updated_at,
            null as created_at,
            null as last_accessed_at,
            null as metadata from folders)
     union all
     (select path_tokens[$1] as "name",
            id,
            updated_at,
            created_at,
            last_accessed_at,
            metadata
     from storage.objects
     where objects.name ilike $2 || $3 || ''%''
       and bucket_id = $4
       and array_length(objects.path_tokens, 1) = $1
     order by ' || v_order_by || ')
     limit $5
     offset $6' using levels, prefix, search, bucketname, limits, offsets;
end;
$_$;


--
-- Name: search_v2(text, text, integer, integer, text, text, text, text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.search_v2(prefix text, bucket_name text, limits integer DEFAULT 100, levels integer DEFAULT 1, start_after text DEFAULT ''::text, sort_order text DEFAULT 'asc'::text, sort_column text DEFAULT 'name'::text, sort_column_after text DEFAULT ''::text) RETURNS TABLE(key text, name text, id uuid, updated_at timestamp with time zone, created_at timestamp with time zone, last_accessed_at timestamp with time zone, metadata jsonb)
    LANGUAGE plpgsql STABLE
    AS $$
DECLARE
    v_sort_col text;
    v_sort_ord text;
    v_limit int;
BEGIN
    -- Cap limit to maximum of 1500 records
    v_limit := LEAST(coalesce(limits, 100), 1500);

    -- Validate and normalize sort_order
    v_sort_ord := lower(coalesce(sort_order, 'asc'));
    IF v_sort_ord NOT IN ('asc', 'desc') THEN
        v_sort_ord := 'asc';
    END IF;

    -- Validate and normalize sort_column
    v_sort_col := lower(coalesce(sort_column, 'name'));
    IF v_sort_col NOT IN ('name', 'updated_at', 'created_at') THEN
        v_sort_col := 'name';
    END IF;

    -- Route to appropriate implementation
    IF v_sort_col = 'name' THEN
        -- Use list_objects_with_delimiter for name sorting (most efficient: O(k * log n))
        RETURN QUERY
        SELECT
            split_part(l.name, '/', levels) AS key,
            l.name AS name,
            l.id,
            l.updated_at,
            l.created_at,
            l.last_accessed_at,
            l.metadata
        FROM storage.list_objects_with_delimiter(
            bucket_name,
            coalesce(prefix, ''),
            '/',
            v_limit,
            start_after,
            '',
            v_sort_ord
        ) l;
    ELSE
        -- Use aggregation approach for timestamp sorting
        -- Not efficient for large datasets but supports correct pagination
        RETURN QUERY SELECT * FROM storage.search_by_timestamp(
            prefix, bucket_name, v_limit, levels, start_after,
            v_sort_ord, v_sort_col, sort_column_after
        );
    END IF;
END;
$$;


--
-- Name: update_updated_at_column(); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW; 
END;
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: audit_log_entries; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.audit_log_entries (
    instance_id uuid,
    id uuid NOT NULL,
    payload json,
    created_at timestamp with time zone,
    ip_address character varying(64) DEFAULT ''::character varying NOT NULL
);


--
-- Name: TABLE audit_log_entries; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.audit_log_entries IS 'Auth: Audit trail for user actions.';


--
-- Name: flow_state; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.flow_state (
    id uuid NOT NULL,
    user_id uuid,
    auth_code text,
    code_challenge_method auth.code_challenge_method,
    code_challenge text,
    provider_type text NOT NULL,
    provider_access_token text,
    provider_refresh_token text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    authentication_method text NOT NULL,
    auth_code_issued_at timestamp with time zone,
    invite_token text,
    referrer text,
    oauth_client_state_id uuid,
    linking_target_id uuid,
    email_optional boolean DEFAULT false NOT NULL
);


--
-- Name: TABLE flow_state; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.flow_state IS 'Stores metadata for all OAuth/SSO login flows';


--
-- Name: identities; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.identities (
    provider_id text NOT NULL,
    user_id uuid NOT NULL,
    identity_data jsonb NOT NULL,
    provider text NOT NULL,
    last_sign_in_at timestamp with time zone,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    email text GENERATED ALWAYS AS (lower((identity_data ->> 'email'::text))) STORED,
    id uuid DEFAULT gen_random_uuid() NOT NULL
);


--
-- Name: TABLE identities; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.identities IS 'Auth: Stores identities associated to a user.';


--
-- Name: COLUMN identities.email; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN auth.identities.email IS 'Auth: Email is a generated column that references the optional email property in the identity_data';


--
-- Name: instances; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.instances (
    id uuid NOT NULL,
    uuid uuid,
    raw_base_config text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);


--
-- Name: TABLE instances; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.instances IS 'Auth: Manages users across multiple sites.';


--
-- Name: mfa_amr_claims; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.mfa_amr_claims (
    session_id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    authentication_method text NOT NULL,
    id uuid NOT NULL
);


--
-- Name: TABLE mfa_amr_claims; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.mfa_amr_claims IS 'auth: stores authenticator method reference claims for multi factor authentication';


--
-- Name: mfa_challenges; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.mfa_challenges (
    id uuid NOT NULL,
    factor_id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    verified_at timestamp with time zone,
    ip_address inet NOT NULL,
    otp_code text,
    web_authn_session_data jsonb
);


--
-- Name: TABLE mfa_challenges; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.mfa_challenges IS 'auth: stores metadata about challenge requests made';


--
-- Name: mfa_factors; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.mfa_factors (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    friendly_name text,
    factor_type auth.factor_type NOT NULL,
    status auth.factor_status NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    secret text,
    phone text,
    last_challenged_at timestamp with time zone,
    web_authn_credential jsonb,
    web_authn_aaguid uuid,
    last_webauthn_challenge_data jsonb
);


--
-- Name: TABLE mfa_factors; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.mfa_factors IS 'auth: stores metadata about factors';


--
-- Name: COLUMN mfa_factors.last_webauthn_challenge_data; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN auth.mfa_factors.last_webauthn_challenge_data IS 'Stores the latest WebAuthn challenge data including attestation/assertion for customer verification';


--
-- Name: oauth_authorizations; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.oauth_authorizations (
    id uuid NOT NULL,
    authorization_id text NOT NULL,
    client_id uuid NOT NULL,
    user_id uuid,
    redirect_uri text NOT NULL,
    scope text NOT NULL,
    state text,
    resource text,
    code_challenge text,
    code_challenge_method auth.code_challenge_method,
    response_type auth.oauth_response_type DEFAULT 'code'::auth.oauth_response_type NOT NULL,
    status auth.oauth_authorization_status DEFAULT 'pending'::auth.oauth_authorization_status NOT NULL,
    authorization_code text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone DEFAULT (now() + '00:03:00'::interval) NOT NULL,
    approved_at timestamp with time zone,
    nonce text,
    CONSTRAINT oauth_authorizations_authorization_code_length CHECK ((char_length(authorization_code) <= 255)),
    CONSTRAINT oauth_authorizations_code_challenge_length CHECK ((char_length(code_challenge) <= 128)),
    CONSTRAINT oauth_authorizations_expires_at_future CHECK ((expires_at > created_at)),
    CONSTRAINT oauth_authorizations_nonce_length CHECK ((char_length(nonce) <= 255)),
    CONSTRAINT oauth_authorizations_redirect_uri_length CHECK ((char_length(redirect_uri) <= 2048)),
    CONSTRAINT oauth_authorizations_resource_length CHECK ((char_length(resource) <= 2048)),
    CONSTRAINT oauth_authorizations_scope_length CHECK ((char_length(scope) <= 4096)),
    CONSTRAINT oauth_authorizations_state_length CHECK ((char_length(state) <= 4096))
);


--
-- Name: oauth_client_states; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.oauth_client_states (
    id uuid NOT NULL,
    provider_type text NOT NULL,
    code_verifier text,
    created_at timestamp with time zone NOT NULL
);


--
-- Name: TABLE oauth_client_states; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.oauth_client_states IS 'Stores OAuth states for third-party provider authentication flows where Supabase acts as the OAuth client.';


--
-- Name: oauth_clients; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.oauth_clients (
    id uuid NOT NULL,
    client_secret_hash text,
    registration_type auth.oauth_registration_type NOT NULL,
    redirect_uris text NOT NULL,
    grant_types text NOT NULL,
    client_name text,
    client_uri text,
    logo_uri text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    client_type auth.oauth_client_type DEFAULT 'confidential'::auth.oauth_client_type NOT NULL,
    token_endpoint_auth_method text NOT NULL,
    CONSTRAINT oauth_clients_client_name_length CHECK ((char_length(client_name) <= 1024)),
    CONSTRAINT oauth_clients_client_uri_length CHECK ((char_length(client_uri) <= 2048)),
    CONSTRAINT oauth_clients_logo_uri_length CHECK ((char_length(logo_uri) <= 2048)),
    CONSTRAINT oauth_clients_token_endpoint_auth_method_check CHECK ((token_endpoint_auth_method = ANY (ARRAY['client_secret_basic'::text, 'client_secret_post'::text, 'none'::text])))
);


--
-- Name: oauth_consents; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.oauth_consents (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    client_id uuid NOT NULL,
    scopes text NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    CONSTRAINT oauth_consents_revoked_after_granted CHECK (((revoked_at IS NULL) OR (revoked_at >= granted_at))),
    CONSTRAINT oauth_consents_scopes_length CHECK ((char_length(scopes) <= 2048)),
    CONSTRAINT oauth_consents_scopes_not_empty CHECK ((char_length(TRIM(BOTH FROM scopes)) > 0))
);


--
-- Name: one_time_tokens; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.one_time_tokens (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    token_type auth.one_time_token_type NOT NULL,
    token_hash text NOT NULL,
    relates_to text NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT one_time_tokens_token_hash_check CHECK ((char_length(token_hash) > 0))
);


--
-- Name: refresh_tokens; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.refresh_tokens (
    instance_id uuid,
    id bigint NOT NULL,
    token character varying(255),
    user_id character varying(255),
    revoked boolean,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    parent character varying(255),
    session_id uuid
);


--
-- Name: TABLE refresh_tokens; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.refresh_tokens IS 'Auth: Store of tokens used to refresh JWT tokens once they expire.';


--
-- Name: refresh_tokens_id_seq; Type: SEQUENCE; Schema: auth; Owner: -
--

CREATE SEQUENCE auth.refresh_tokens_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: refresh_tokens_id_seq; Type: SEQUENCE OWNED BY; Schema: auth; Owner: -
--

ALTER SEQUENCE auth.refresh_tokens_id_seq OWNED BY auth.refresh_tokens.id;


--
-- Name: saml_providers; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.saml_providers (
    id uuid NOT NULL,
    sso_provider_id uuid NOT NULL,
    entity_id text NOT NULL,
    metadata_xml text NOT NULL,
    metadata_url text,
    attribute_mapping jsonb,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    name_id_format text,
    CONSTRAINT "entity_id not empty" CHECK ((char_length(entity_id) > 0)),
    CONSTRAINT "metadata_url not empty" CHECK (((metadata_url = NULL::text) OR (char_length(metadata_url) > 0))),
    CONSTRAINT "metadata_xml not empty" CHECK ((char_length(metadata_xml) > 0))
);


--
-- Name: TABLE saml_providers; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.saml_providers IS 'Auth: Manages SAML Identity Provider connections.';


--
-- Name: saml_relay_states; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.saml_relay_states (
    id uuid NOT NULL,
    sso_provider_id uuid NOT NULL,
    request_id text NOT NULL,
    for_email text,
    redirect_to text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    flow_state_id uuid,
    CONSTRAINT "request_id not empty" CHECK ((char_length(request_id) > 0))
);


--
-- Name: TABLE saml_relay_states; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.saml_relay_states IS 'Auth: Contains SAML Relay State information for each Service Provider initiated login.';


--
-- Name: schema_migrations; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.schema_migrations (
    version character varying(255) NOT NULL
);


--
-- Name: TABLE schema_migrations; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.schema_migrations IS 'Auth: Manages updates to the auth system.';


--
-- Name: sessions; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.sessions (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    factor_id uuid,
    aal auth.aal_level,
    not_after timestamp with time zone,
    refreshed_at timestamp without time zone,
    user_agent text,
    ip inet,
    tag text,
    oauth_client_id uuid,
    refresh_token_hmac_key text,
    refresh_token_counter bigint,
    scopes text,
    CONSTRAINT sessions_scopes_length CHECK ((char_length(scopes) <= 4096))
);


--
-- Name: TABLE sessions; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.sessions IS 'Auth: Stores session data associated to a user.';


--
-- Name: COLUMN sessions.not_after; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN auth.sessions.not_after IS 'Auth: Not after is a nullable column that contains a timestamp after which the session should be regarded as expired.';


--
-- Name: COLUMN sessions.refresh_token_hmac_key; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN auth.sessions.refresh_token_hmac_key IS 'Holds a HMAC-SHA256 key used to sign refresh tokens for this session.';


--
-- Name: COLUMN sessions.refresh_token_counter; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN auth.sessions.refresh_token_counter IS 'Holds the ID (counter) of the last issued refresh token.';


--
-- Name: sso_domains; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.sso_domains (
    id uuid NOT NULL,
    sso_provider_id uuid NOT NULL,
    domain text NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    CONSTRAINT "domain not empty" CHECK ((char_length(domain) > 0))
);


--
-- Name: TABLE sso_domains; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.sso_domains IS 'Auth: Manages SSO email address domain mapping to an SSO Identity Provider.';


--
-- Name: sso_providers; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.sso_providers (
    id uuid NOT NULL,
    resource_id text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    disabled boolean,
    CONSTRAINT "resource_id not empty" CHECK (((resource_id = NULL::text) OR (char_length(resource_id) > 0)))
);


--
-- Name: TABLE sso_providers; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.sso_providers IS 'Auth: Manages SSO identity provider information; see saml_providers for SAML.';


--
-- Name: COLUMN sso_providers.resource_id; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN auth.sso_providers.resource_id IS 'Auth: Uniquely identifies a SSO provider according to a user-chosen resource ID (case insensitive), useful in infrastructure as code.';


--
-- Name: users; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.users (
    instance_id uuid,
    id uuid NOT NULL,
    aud character varying(255),
    role character varying(255),
    email character varying(255),
    encrypted_password character varying(255),
    email_confirmed_at timestamp with time zone,
    invited_at timestamp with time zone,
    confirmation_token character varying(255),
    confirmation_sent_at timestamp with time zone,
    recovery_token character varying(255),
    recovery_sent_at timestamp with time zone,
    email_change_token_new character varying(255),
    email_change character varying(255),
    email_change_sent_at timestamp with time zone,
    last_sign_in_at timestamp with time zone,
    raw_app_meta_data jsonb,
    raw_user_meta_data jsonb,
    is_super_admin boolean,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    phone text DEFAULT NULL::character varying,
    phone_confirmed_at timestamp with time zone,
    phone_change text DEFAULT ''::character varying,
    phone_change_token character varying(255) DEFAULT ''::character varying,
    phone_change_sent_at timestamp with time zone,
    confirmed_at timestamp with time zone GENERATED ALWAYS AS (LEAST(email_confirmed_at, phone_confirmed_at)) STORED,
    email_change_token_current character varying(255) DEFAULT ''::character varying,
    email_change_confirm_status smallint DEFAULT 0,
    banned_until timestamp with time zone,
    reauthentication_token character varying(255) DEFAULT ''::character varying,
    reauthentication_sent_at timestamp with time zone,
    is_sso_user boolean DEFAULT false NOT NULL,
    deleted_at timestamp with time zone,
    is_anonymous boolean DEFAULT false NOT NULL,
    CONSTRAINT users_email_change_confirm_status_check CHECK (((email_change_confirm_status >= 0) AND (email_change_confirm_status <= 2)))
);


--
-- Name: TABLE users; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.users IS 'Auth: Stores user login data within a secure schema.';


--
-- Name: COLUMN users.is_sso_user; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN auth.users.is_sso_user IS 'Auth: Set this column to true when the account comes from SSO. These accounts can have duplicate emails.';


--
-- Name: availability_calendar; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.availability_calendar (
    id uuid DEFAULT extensions.uuid_generate_v4() NOT NULL,
    equipment_id uuid NOT NULL,
    date date NOT NULL,
    is_available boolean DEFAULT true,
    custom_rate numeric(8,2),
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: equipment; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.equipment (
    id uuid DEFAULT extensions.uuid_generate_v4() NOT NULL,
    owner_id uuid NOT NULL,
    category_id uuid NOT NULL,
    title text NOT NULL,
    description text NOT NULL,
    daily_rate numeric(8,2) NOT NULL,
    condition public.equipment_condition NOT NULL,
    location text NOT NULL,
    latitude numeric(10,8),
    longitude numeric(11,8),
    is_available boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    damage_deposit_amount numeric(10,2),
    damage_deposit_percentage integer,
    deposit_refund_timeline_hours integer DEFAULT 48,
    CONSTRAINT equipment_damage_deposit_percentage_check CHECK (((damage_deposit_percentage >= 0) AND (damage_deposit_percentage <= 100)))
);


--
-- Name: COLUMN equipment.damage_deposit_amount; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.equipment.damage_deposit_amount IS 'Fixed damage deposit amount in dollars';


--
-- Name: COLUMN equipment.damage_deposit_percentage; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.equipment.damage_deposit_percentage IS 'Damage deposit as percentage of daily rate (0-100)';


--
-- Name: COLUMN equipment.deposit_refund_timeline_hours; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.equipment.deposit_refund_timeline_hours IS 'Hours after return before deposit is auto-released (default 48)';


--
-- Name: available_equipment_counts_by_category; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.available_equipment_counts_by_category WITH (security_invoker='true') AS
 SELECT category_id,
    (count(*))::integer AS available_count
   FROM public.equipment
  WHERE (is_available = true)
  GROUP BY category_id;


--
-- Name: booking_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.booking_history (
    id uuid DEFAULT extensions.uuid_generate_v4() NOT NULL,
    booking_request_id uuid NOT NULL,
    old_status public.booking_status,
    new_status public.booking_status NOT NULL,
    changed_by uuid,
    changed_at timestamp with time zone DEFAULT now(),
    reason text,
    metadata jsonb
);


--
-- Name: booking_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.booking_requests (
    id uuid DEFAULT extensions.uuid_generate_v4() NOT NULL,
    equipment_id uuid NOT NULL,
    renter_id uuid NOT NULL,
    start_date date NOT NULL,
    end_date date NOT NULL,
    total_amount numeric(10,2) NOT NULL,
    status public.booking_status DEFAULT 'pending'::public.booking_status,
    message text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    insurance_type text,
    insurance_cost numeric(10,2) DEFAULT 0,
    damage_deposit_amount numeric(10,2) DEFAULT 0,
    renter_reviewed_at timestamp with time zone,
    owner_reviewed_at timestamp with time zone,
    completed_at timestamp with time zone,
    activated_at timestamp with time zone,
    status_updated_at timestamp with time zone DEFAULT now(),
    disputed_at timestamp with time zone,
    CONSTRAINT booking_requests_insurance_type_check CHECK ((insurance_type = ANY (ARRAY['none'::text, 'basic'::text, 'premium'::text]))),
    CONSTRAINT check_valid_date_range CHECK ((end_date >= start_date))
);


--
-- Name: COLUMN booking_requests.insurance_type; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.booking_requests.insurance_type IS 'Type of insurance selected: none, basic (5%), or premium (10%)';


--
-- Name: COLUMN booking_requests.insurance_cost; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.booking_requests.insurance_cost IS 'Calculated insurance cost based on rental amount';


--
-- Name: COLUMN booking_requests.damage_deposit_amount; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.booking_requests.damage_deposit_amount IS 'Damage deposit amount for this booking';


--
-- Name: COLUMN booking_requests.status_updated_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.booking_requests.status_updated_at IS 'Timestamp of last status change';


--
-- Name: COLUMN booking_requests.disputed_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.booking_requests.disputed_at IS 'Timestamp when rental entered disputed state';


--
-- Name: bookings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.bookings (
    id uuid DEFAULT extensions.uuid_generate_v4() NOT NULL,
    booking_request_id uuid NOT NULL,
    payment_status text DEFAULT 'pending'::text,
    pickup_method text,
    return_status text DEFAULT 'pending'::text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: categories; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.categories (
    id uuid DEFAULT extensions.uuid_generate_v4() NOT NULL,
    name text NOT NULL,
    parent_id uuid,
    sport_type text NOT NULL,
    attributes jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: content_translations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.content_translations (
    id uuid DEFAULT extensions.uuid_generate_v4() NOT NULL,
    content_type character varying(50) NOT NULL,
    content_id uuid NOT NULL,
    field_name character varying(50) NOT NULL,
    source_lang character varying(5) DEFAULT 'en'::character varying NOT NULL,
    target_lang character varying(5) NOT NULL,
    original_text text NOT NULL,
    translated_text text NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: TABLE content_translations; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.content_translations IS 'Caches translations of user-generated content. Write access restricted to content owners or service role to prevent tampering.';


--
-- Name: conversation_participants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.conversation_participants (
    id uuid DEFAULT extensions.uuid_generate_v4() NOT NULL,
    conversation_id uuid NOT NULL,
    profile_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    last_read_at timestamp with time zone
);


--
-- Name: TABLE conversation_participants; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.conversation_participants IS 'Junction table linking conversations to participant profiles (many-to-many relationship)';


--
-- Name: COLUMN conversation_participants.last_read_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.conversation_participants.last_read_at IS 'Timestamp when the participant last read messages in this conversation. NULL indicates unread or never read.';


--
-- Name: conversations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.conversations (
    id uuid DEFAULT extensions.uuid_generate_v4() NOT NULL,
    booking_request_id uuid,
    participants uuid[] NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: damage_claims; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.damage_claims (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    booking_id uuid NOT NULL,
    filed_by uuid NOT NULL,
    filed_at timestamp with time zone DEFAULT now() NOT NULL,
    damage_description text NOT NULL,
    evidence_photos text[] DEFAULT '{}'::text[] NOT NULL,
    estimated_cost numeric(10,2) NOT NULL,
    repair_quotes text[] DEFAULT '{}'::text[],
    status public.claim_status DEFAULT 'pending'::public.claim_status NOT NULL,
    renter_response jsonb,
    resolution jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: TABLE damage_claims; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.damage_claims IS 'Damage claims filed by owners after equipment return. Includes evidence photos, repair quotes, and renter responses.';


--
-- Name: equipment_inspections; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.equipment_inspections (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    booking_id uuid NOT NULL,
    inspection_type public.inspection_type NOT NULL,
    photos text[] DEFAULT '{}'::text[] NOT NULL,
    condition_notes text,
    checklist_items jsonb DEFAULT '[]'::jsonb,
    verified_by_owner boolean DEFAULT false,
    verified_by_renter boolean DEFAULT false,
    owner_signature text,
    renter_signature text,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL,
    location jsonb,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: TABLE equipment_inspections; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.equipment_inspections IS 'Records equipment condition inspections at pickup and return. Both owner and renter verify condition with photos, checklists, and digital signatures.';


--
-- Name: equipment_photos; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.equipment_photos (
    id uuid DEFAULT extensions.uuid_generate_v4() NOT NULL,
    equipment_id uuid NOT NULL,
    photo_url text NOT NULL,
    is_primary boolean DEFAULT false,
    order_index integer DEFAULT 0,
    created_at timestamp with time zone DEFAULT now(),
    alt text,
    description text
);


--
-- Name: COLUMN equipment_photos.alt; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.equipment_photos.alt IS 'Accessibility text for the photo (used in img alt attribute)';


--
-- Name: COLUMN equipment_photos.description; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.equipment_photos.description IS 'Optional description of the photo content';


--
-- Name: messages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.messages (
    id uuid DEFAULT extensions.uuid_generate_v4() NOT NULL,
    conversation_id uuid NOT NULL,
    sender_id uuid NOT NULL,
    content text NOT NULL,
    message_type text DEFAULT 'text'::text,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: profiles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.profiles (
    id uuid DEFAULT extensions.uuid_generate_v4() NOT NULL,
    email text NOT NULL,
    role public.user_role NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    last_seen_at timestamp with time zone,
    identity_verified boolean DEFAULT false,
    phone_verified boolean DEFAULT false,
    email_verified boolean DEFAULT false,
    address_verified boolean DEFAULT false,
    verified_at timestamp with time zone,
    username text,
    full_name text,
    avatar_url text,
    trust_score integer DEFAULT 0,
    trust_score_updated_at timestamp with time zone,
    average_response_time_hours numeric(5,2) DEFAULT NULL::numeric
);


--
-- Name: COLUMN profiles.identity_verified; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.profiles.identity_verified IS 'Whether user has completed identity verification';


--
-- Name: COLUMN profiles.phone_verified; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.profiles.phone_verified IS 'Whether user has verified their phone number';


--
-- Name: COLUMN profiles.email_verified; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.profiles.email_verified IS 'Whether user has verified their email address';


--
-- Name: COLUMN profiles.address_verified; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.profiles.address_verified IS 'Whether user has verified their physical address';


--
-- Name: COLUMN profiles.verified_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.profiles.verified_at IS 'Timestamp when user completed full verification';


--
-- Name: COLUMN profiles.username; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.profiles.username IS 'Unique username for display (e.g., @johndoe)';


--
-- Name: COLUMN profiles.full_name; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.profiles.full_name IS 'Full display name (e.g., John Doe)';


--
-- Name: COLUMN profiles.avatar_url; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.profiles.avatar_url IS 'URL to profile avatar image';


--
-- Name: messaging_conversation_summaries; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.messaging_conversation_summaries WITH (security_invoker='true') AS
 WITH latest_message AS (
         SELECT DISTINCT ON (messages.conversation_id) messages.conversation_id,
            messages.id AS message_id,
            messages.sender_id,
            messages.content,
            messages.message_type,
            messages.created_at
           FROM public.messages
          ORDER BY messages.conversation_id, messages.created_at DESC
        ), unread AS (
         SELECT cp_1.conversation_id,
            cp_1.profile_id,
            count(m.id) AS unread_count
           FROM (public.conversation_participants cp_1
             JOIN public.messages m ON (((m.conversation_id = cp_1.conversation_id) AND (m.created_at > COALESCE(cp_1.last_read_at, cp_1.created_at, (m.created_at - '100 years'::interval))) AND (m.sender_id <> cp_1.profile_id))))
          GROUP BY cp_1.conversation_id, cp_1.profile_id
        )
 SELECT c.id,
    c.booking_request_id,
    c.created_at,
    c.updated_at,
    lm.message_id AS last_message_id,
    lm.sender_id AS last_message_sender_id,
    lm.content AS last_message_content,
    lm.message_type AS last_message_type,
    lm.created_at AS last_message_created_at,
    cp.profile_id AS participant_id,
    p.email AS participant_email,
    p.last_seen_at,
    br.status AS booking_status,
    br.start_date,
    br.end_date,
    br.total_amount,
    e.title AS equipment_title,
    COALESCE(u.unread_count, (0)::bigint) AS unread_count
   FROM ((((((public.conversations c
     JOIN public.conversation_participants cp ON ((cp.conversation_id = c.id)))
     JOIN public.profiles p ON ((p.id = cp.profile_id)))
     LEFT JOIN latest_message lm ON ((lm.conversation_id = c.id)))
     LEFT JOIN public.booking_requests br ON ((br.id = c.booking_request_id)))
     LEFT JOIN public.equipment e ON ((e.id = br.equipment_id)))
     LEFT JOIN unread u ON (((u.conversation_id = cp.conversation_id) AND (u.profile_id = cp.profile_id))));


--
-- Name: notification_preferences; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.notification_preferences (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    booking_notifications boolean DEFAULT true NOT NULL,
    message_notifications boolean DEFAULT true NOT NULL,
    payment_notifications boolean DEFAULT true NOT NULL,
    review_notifications boolean DEFAULT true NOT NULL,
    verification_notifications boolean DEFAULT true NOT NULL,
    equipment_notifications boolean DEFAULT true NOT NULL,
    system_notifications boolean DEFAULT true NOT NULL,
    promotion_notifications boolean DEFAULT true NOT NULL,
    toast_critical boolean DEFAULT true NOT NULL,
    toast_high boolean DEFAULT true NOT NULL,
    toast_medium boolean DEFAULT false NOT NULL,
    toast_low boolean DEFAULT false NOT NULL,
    quiet_hours_enabled boolean DEFAULT false NOT NULL,
    quiet_hours_start time without time zone,
    quiet_hours_end time without time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE notification_preferences; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.notification_preferences IS 'User preferences for in-app notification behavior';


--
-- Name: COLUMN notification_preferences.toast_critical; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.notification_preferences.toast_critical IS 'Show toast popups for critical notifications (payments, refunds)';


--
-- Name: COLUMN notification_preferences.quiet_hours_enabled; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.notification_preferences.quiet_hours_enabled IS 'When enabled, suppress toast notifications during quiet hours';


--
-- Name: notifications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.notifications (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    type public.notification_type NOT NULL,
    priority public.notification_priority DEFAULT 'medium'::public.notification_priority NOT NULL,
    title text NOT NULL,
    message text NOT NULL,
    related_entity_type text,
    related_entity_id uuid,
    actor_id uuid,
    is_read boolean DEFAULT false NOT NULL,
    read_at timestamp with time zone,
    is_archived boolean DEFAULT false NOT NULL,
    archived_at timestamp with time zone,
    group_key text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE notifications; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.notifications IS 'In-app notifications for users';


--
-- Name: COLUMN notifications.priority; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.notifications.priority IS 'Used to determine if a toast popup should be shown';


--
-- Name: COLUMN notifications.related_entity_type; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.notifications.related_entity_type IS 'Type of entity this notification links to: booking, equipment, conversation, review, payment';


--
-- Name: COLUMN notifications.group_key; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.notifications.group_key IS 'Key for grouping similar notifications, e.g., messages:conversation_id';


--
-- Name: owner_profiles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.owner_profiles (
    id uuid DEFAULT extensions.uuid_generate_v4() NOT NULL,
    profile_id uuid NOT NULL,
    business_info jsonb,
    earnings_total numeric(10,2) DEFAULT 0,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: TABLE owner_profiles; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.owner_profiles IS 'Owner-specific profile data. Verification is tracked in the base profiles table.';


--
-- Name: payments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.payments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    booking_request_id uuid,
    renter_id uuid NOT NULL,
    owner_id uuid NOT NULL,
    stripe_payment_intent_id text,
    stripe_charge_id text,
    subtotal numeric(10,2) NOT NULL,
    service_fee numeric(10,2) DEFAULT 0 NOT NULL,
    tax numeric(10,2) DEFAULT 0 NOT NULL,
    total_amount numeric(10,2) NOT NULL,
    escrow_amount numeric(10,2) NOT NULL,
    escrow_status text DEFAULT 'held'::text NOT NULL,
    escrow_released_at timestamp with time zone,
    owner_payout_amount numeric(10,2) NOT NULL,
    payout_status text DEFAULT 'pending'::text NOT NULL,
    payout_processed_at timestamp with time zone,
    stripe_transfer_id text,
    payment_status text DEFAULT 'pending'::text NOT NULL,
    payment_method_id text,
    currency text DEFAULT 'usd'::text NOT NULL,
    refund_amount numeric(10,2) DEFAULT 0,
    refund_reason text,
    failure_reason text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    rental_amount numeric(10,2),
    deposit_amount numeric(10,2) DEFAULT 0,
    insurance_amount numeric(10,2) DEFAULT 0,
    deposit_status public.deposit_status DEFAULT 'held'::public.deposit_status,
    deposit_released_at timestamp with time zone,
    CONSTRAINT payments_escrow_status_check CHECK ((escrow_status = ANY (ARRAY['held'::text, 'released'::text, 'refunded'::text, 'disputed'::text]))),
    CONSTRAINT payments_payment_status_check CHECK ((payment_status = ANY (ARRAY['pending'::text, 'processing'::text, 'succeeded'::text, 'failed'::text, 'refunded'::text, 'cancelled'::text]))),
    CONSTRAINT payments_payout_status_check CHECK ((payout_status = ANY (ARRAY['pending'::text, 'processing'::text, 'completed'::text, 'failed'::text]))),
    CONSTRAINT valid_amounts CHECK ((total_amount = ((((subtotal + service_fee) + tax) + COALESCE(insurance_amount, (0)::numeric)) + COALESCE(deposit_amount, (0)::numeric)))),
    CONSTRAINT valid_escrow CHECK ((escrow_amount <= total_amount)),
    CONSTRAINT valid_payout CHECK ((owner_payout_amount <= escrow_amount))
);


--
-- Name: COLUMN payments.rental_amount; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.payments.rental_amount IS 'Base rental amount (excluding fees, deposit, insurance)';


--
-- Name: COLUMN payments.deposit_amount; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.payments.deposit_amount IS 'Damage deposit amount held in escrow';


--
-- Name: COLUMN payments.insurance_amount; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.payments.insurance_amount IS 'Insurance fee charged to renter';


--
-- Name: COLUMN payments.deposit_status; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.payments.deposit_status IS 'Status of damage deposit: held, released, claimed, or refunded';


--
-- Name: COLUMN payments.deposit_released_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.payments.deposit_released_at IS 'Timestamp when deposit was released back to renter';


--
-- Name: CONSTRAINT valid_amounts ON payments; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON CONSTRAINT valid_amounts ON public.payments IS 'total_amount equals subtotal + service_fee + tax + insurance_amount + deposit_amount';


--
-- Name: rental_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rental_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    booking_id uuid NOT NULL,
    event_type text NOT NULL,
    event_data jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    created_by uuid,
    CONSTRAINT rental_events_event_type_check CHECK ((event_type = ANY (ARRAY['pickup_confirmed'::text, 'rental_started'::text, 'return_confirmed'::text, 'rental_completed'::text, 'review_submitted'::text, 'deposit_released'::text])))
);


--
-- Name: TABLE rental_events; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.rental_events IS 'Audit trail for rental lifecycle events';


--
-- Name: renter_profiles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.renter_profiles (
    id uuid DEFAULT extensions.uuid_generate_v4() NOT NULL,
    profile_id uuid NOT NULL,
    preferences jsonb,
    experience_level text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: TABLE renter_profiles; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.renter_profiles IS 'Renter-specific profile data. Verification is tracked in the base profiles table.';


--
-- Name: reviews; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.reviews (
    id uuid DEFAULT extensions.uuid_generate_v4() NOT NULL,
    booking_id uuid NOT NULL,
    reviewer_id uuid NOT NULL,
    reviewee_id uuid NOT NULL,
    rating integer NOT NULL,
    comment text,
    photos jsonb,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT reviews_rating_check CHECK (((rating >= 1) AND (rating <= 5)))
);


--
-- Name: user_favorites; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_favorites (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    equipment_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: user_verifications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_verifications (
    id uuid DEFAULT extensions.uuid_generate_v4() NOT NULL,
    user_id uuid NOT NULL,
    verification_type text NOT NULL,
    status public.verification_status DEFAULT 'pending'::public.verification_status,
    document_url text,
    verified_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    rejection_reason text
);


--
-- Name: COLUMN user_verifications.rejection_reason; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.user_verifications.rejection_reason IS 'Reason provided by admin when rejecting a verification document';


--
-- Name: messages; Type: TABLE; Schema: realtime; Owner: -
--

CREATE TABLE realtime.messages (
    topic text NOT NULL,
    extension text NOT NULL,
    payload jsonb,
    event text,
    private boolean DEFAULT false,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    inserted_at timestamp without time zone DEFAULT now() NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL
)
PARTITION BY RANGE (inserted_at);


--
-- Name: messages_2026_02_17; Type: TABLE; Schema: realtime; Owner: -
--

CREATE TABLE realtime.messages_2026_02_17 (
    topic text NOT NULL,
    extension text NOT NULL,
    payload jsonb,
    event text,
    private boolean DEFAULT false,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    inserted_at timestamp without time zone DEFAULT now() NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL
);


--
-- Name: messages_2026_02_18; Type: TABLE; Schema: realtime; Owner: -
--

CREATE TABLE realtime.messages_2026_02_18 (
    topic text NOT NULL,
    extension text NOT NULL,
    payload jsonb,
    event text,
    private boolean DEFAULT false,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    inserted_at timestamp without time zone DEFAULT now() NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL
);


--
-- Name: messages_2026_02_19; Type: TABLE; Schema: realtime; Owner: -
--

CREATE TABLE realtime.messages_2026_02_19 (
    topic text NOT NULL,
    extension text NOT NULL,
    payload jsonb,
    event text,
    private boolean DEFAULT false,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    inserted_at timestamp without time zone DEFAULT now() NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL
);


--
-- Name: messages_2026_02_20; Type: TABLE; Schema: realtime; Owner: -
--

CREATE TABLE realtime.messages_2026_02_20 (
    topic text NOT NULL,
    extension text NOT NULL,
    payload jsonb,
    event text,
    private boolean DEFAULT false,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    inserted_at timestamp without time zone DEFAULT now() NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL
);


--
-- Name: messages_2026_02_21; Type: TABLE; Schema: realtime; Owner: -
--

CREATE TABLE realtime.messages_2026_02_21 (
    topic text NOT NULL,
    extension text NOT NULL,
    payload jsonb,
    event text,
    private boolean DEFAULT false,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    inserted_at timestamp without time zone DEFAULT now() NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL
);


--
-- Name: messages_2026_02_22; Type: TABLE; Schema: realtime; Owner: -
--

CREATE TABLE realtime.messages_2026_02_22 (
    topic text NOT NULL,
    extension text NOT NULL,
    payload jsonb,
    event text,
    private boolean DEFAULT false,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    inserted_at timestamp without time zone DEFAULT now() NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL
);


--
-- Name: messages_2026_02_23; Type: TABLE; Schema: realtime; Owner: -
--

CREATE TABLE realtime.messages_2026_02_23 (
    topic text NOT NULL,
    extension text NOT NULL,
    payload jsonb,
    event text,
    private boolean DEFAULT false,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    inserted_at timestamp without time zone DEFAULT now() NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL
);


--
-- Name: schema_migrations; Type: TABLE; Schema: realtime; Owner: -
--

CREATE TABLE realtime.schema_migrations (
    version bigint NOT NULL,
    inserted_at timestamp(0) without time zone
);


--
-- Name: subscription; Type: TABLE; Schema: realtime; Owner: -
--

CREATE TABLE realtime.subscription (
    id bigint NOT NULL,
    subscription_id uuid NOT NULL,
    entity regclass NOT NULL,
    filters realtime.user_defined_filter[] DEFAULT '{}'::realtime.user_defined_filter[] NOT NULL,
    claims jsonb NOT NULL,
    claims_role regrole GENERATED ALWAYS AS (realtime.to_regrole((claims ->> 'role'::text))) STORED NOT NULL,
    created_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    action_filter text DEFAULT '*'::text,
    CONSTRAINT subscription_action_filter_check CHECK ((action_filter = ANY (ARRAY['*'::text, 'INSERT'::text, 'UPDATE'::text, 'DELETE'::text])))
);


--
-- Name: subscription_id_seq; Type: SEQUENCE; Schema: realtime; Owner: -
--

ALTER TABLE realtime.subscription ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME realtime.subscription_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: buckets; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE storage.buckets (
    id text NOT NULL,
    name text NOT NULL,
    owner uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    public boolean DEFAULT false,
    avif_autodetection boolean DEFAULT false,
    file_size_limit bigint,
    allowed_mime_types text[],
    owner_id text,
    type storage.buckettype DEFAULT 'STANDARD'::storage.buckettype NOT NULL
);


--
-- Name: COLUMN buckets.owner; Type: COMMENT; Schema: storage; Owner: -
--

COMMENT ON COLUMN storage.buckets.owner IS 'Field is deprecated, use owner_id instead';


--
-- Name: buckets_analytics; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE storage.buckets_analytics (
    name text NOT NULL,
    type storage.buckettype DEFAULT 'ANALYTICS'::storage.buckettype NOT NULL,
    format text DEFAULT 'ICEBERG'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    deleted_at timestamp with time zone
);


--
-- Name: buckets_vectors; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE storage.buckets_vectors (
    id text NOT NULL,
    type storage.buckettype DEFAULT 'VECTOR'::storage.buckettype NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: migrations; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE storage.migrations (
    id integer NOT NULL,
    name character varying(100) NOT NULL,
    hash character varying(40) NOT NULL,
    executed_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: objects; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE storage.objects (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    bucket_id text,
    name text,
    owner uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    last_accessed_at timestamp with time zone DEFAULT now(),
    metadata jsonb,
    path_tokens text[] GENERATED ALWAYS AS (string_to_array(name, '/'::text)) STORED,
    version text,
    owner_id text,
    user_metadata jsonb
);


--
-- Name: COLUMN objects.owner; Type: COMMENT; Schema: storage; Owner: -
--

COMMENT ON COLUMN storage.objects.owner IS 'Field is deprecated, use owner_id instead';


--
-- Name: s3_multipart_uploads; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE storage.s3_multipart_uploads (
    id text NOT NULL,
    in_progress_size bigint DEFAULT 0 NOT NULL,
    upload_signature text NOT NULL,
    bucket_id text NOT NULL,
    key text NOT NULL COLLATE pg_catalog."C",
    version text NOT NULL,
    owner_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    user_metadata jsonb
);


--
-- Name: s3_multipart_uploads_parts; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE storage.s3_multipart_uploads_parts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    upload_id text NOT NULL,
    size bigint DEFAULT 0 NOT NULL,
    part_number integer NOT NULL,
    bucket_id text NOT NULL,
    key text NOT NULL COLLATE pg_catalog."C",
    etag text NOT NULL,
    owner_id text,
    version text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: vector_indexes; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE storage.vector_indexes (
    id text DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL COLLATE pg_catalog."C",
    bucket_id text NOT NULL,
    data_type text NOT NULL,
    dimension integer NOT NULL,
    distance_metric text NOT NULL,
    metadata_configuration jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: schema_migrations; Type: TABLE; Schema: supabase_migrations; Owner: -
--

CREATE TABLE supabase_migrations.schema_migrations (
    version text NOT NULL,
    statements text[],
    name text,
    created_by text,
    idempotency_key text,
    rollback text[]
);


--
-- Name: seed_files; Type: TABLE; Schema: supabase_migrations; Owner: -
--

CREATE TABLE supabase_migrations.seed_files (
    path text NOT NULL,
    hash text NOT NULL
);


--
-- Name: messages_2026_02_17; Type: TABLE ATTACH; Schema: realtime; Owner: -
--

ALTER TABLE ONLY realtime.messages ATTACH PARTITION realtime.messages_2026_02_17 FOR VALUES FROM ('2026-02-17 00:00:00') TO ('2026-02-18 00:00:00');


--
-- Name: messages_2026_02_18; Type: TABLE ATTACH; Schema: realtime; Owner: -
--

ALTER TABLE ONLY realtime.messages ATTACH PARTITION realtime.messages_2026_02_18 FOR VALUES FROM ('2026-02-18 00:00:00') TO ('2026-02-19 00:00:00');


--
-- Name: messages_2026_02_19; Type: TABLE ATTACH; Schema: realtime; Owner: -
--

ALTER TABLE ONLY realtime.messages ATTACH PARTITION realtime.messages_2026_02_19 FOR VALUES FROM ('2026-02-19 00:00:00') TO ('2026-02-20 00:00:00');


--
-- Name: messages_2026_02_20; Type: TABLE ATTACH; Schema: realtime; Owner: -
--

ALTER TABLE ONLY realtime.messages ATTACH PARTITION realtime.messages_2026_02_20 FOR VALUES FROM ('2026-02-20 00:00:00') TO ('2026-02-21 00:00:00');


--
-- Name: messages_2026_02_21; Type: TABLE ATTACH; Schema: realtime; Owner: -
--

ALTER TABLE ONLY realtime.messages ATTACH PARTITION realtime.messages_2026_02_21 FOR VALUES FROM ('2026-02-21 00:00:00') TO ('2026-02-22 00:00:00');


--
-- Name: messages_2026_02_22; Type: TABLE ATTACH; Schema: realtime; Owner: -
--

ALTER TABLE ONLY realtime.messages ATTACH PARTITION realtime.messages_2026_02_22 FOR VALUES FROM ('2026-02-22 00:00:00') TO ('2026-02-23 00:00:00');


--
-- Name: messages_2026_02_23; Type: TABLE ATTACH; Schema: realtime; Owner: -
--

ALTER TABLE ONLY realtime.messages ATTACH PARTITION realtime.messages_2026_02_23 FOR VALUES FROM ('2026-02-23 00:00:00') TO ('2026-02-24 00:00:00');


--
-- Name: refresh_tokens id; Type: DEFAULT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.refresh_tokens ALTER COLUMN id SET DEFAULT nextval('auth.refresh_tokens_id_seq'::regclass);


--
-- Name: mfa_amr_claims amr_id_pk; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_amr_claims
    ADD CONSTRAINT amr_id_pk PRIMARY KEY (id);


--
-- Name: audit_log_entries audit_log_entries_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.audit_log_entries
    ADD CONSTRAINT audit_log_entries_pkey PRIMARY KEY (id);


--
-- Name: flow_state flow_state_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.flow_state
    ADD CONSTRAINT flow_state_pkey PRIMARY KEY (id);


--
-- Name: identities identities_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.identities
    ADD CONSTRAINT identities_pkey PRIMARY KEY (id);


--
-- Name: identities identities_provider_id_provider_unique; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.identities
    ADD CONSTRAINT identities_provider_id_provider_unique UNIQUE (provider_id, provider);


--
-- Name: instances instances_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.instances
    ADD CONSTRAINT instances_pkey PRIMARY KEY (id);


--
-- Name: mfa_amr_claims mfa_amr_claims_session_id_authentication_method_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_amr_claims
    ADD CONSTRAINT mfa_amr_claims_session_id_authentication_method_pkey UNIQUE (session_id, authentication_method);


--
-- Name: mfa_challenges mfa_challenges_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_challenges
    ADD CONSTRAINT mfa_challenges_pkey PRIMARY KEY (id);


--
-- Name: mfa_factors mfa_factors_last_challenged_at_key; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_factors
    ADD CONSTRAINT mfa_factors_last_challenged_at_key UNIQUE (last_challenged_at);


--
-- Name: mfa_factors mfa_factors_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_factors
    ADD CONSTRAINT mfa_factors_pkey PRIMARY KEY (id);


--
-- Name: oauth_authorizations oauth_authorizations_authorization_code_key; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oauth_authorizations
    ADD CONSTRAINT oauth_authorizations_authorization_code_key UNIQUE (authorization_code);


--
-- Name: oauth_authorizations oauth_authorizations_authorization_id_key; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oauth_authorizations
    ADD CONSTRAINT oauth_authorizations_authorization_id_key UNIQUE (authorization_id);


--
-- Name: oauth_authorizations oauth_authorizations_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oauth_authorizations
    ADD CONSTRAINT oauth_authorizations_pkey PRIMARY KEY (id);


--
-- Name: oauth_client_states oauth_client_states_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oauth_client_states
    ADD CONSTRAINT oauth_client_states_pkey PRIMARY KEY (id);


--
-- Name: oauth_clients oauth_clients_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oauth_clients
    ADD CONSTRAINT oauth_clients_pkey PRIMARY KEY (id);


--
-- Name: oauth_consents oauth_consents_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oauth_consents
    ADD CONSTRAINT oauth_consents_pkey PRIMARY KEY (id);


--
-- Name: oauth_consents oauth_consents_user_client_unique; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oauth_consents
    ADD CONSTRAINT oauth_consents_user_client_unique UNIQUE (user_id, client_id);


--
-- Name: one_time_tokens one_time_tokens_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.one_time_tokens
    ADD CONSTRAINT one_time_tokens_pkey PRIMARY KEY (id);


--
-- Name: refresh_tokens refresh_tokens_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.refresh_tokens
    ADD CONSTRAINT refresh_tokens_pkey PRIMARY KEY (id);


--
-- Name: refresh_tokens refresh_tokens_token_unique; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.refresh_tokens
    ADD CONSTRAINT refresh_tokens_token_unique UNIQUE (token);


--
-- Name: saml_providers saml_providers_entity_id_key; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.saml_providers
    ADD CONSTRAINT saml_providers_entity_id_key UNIQUE (entity_id);


--
-- Name: saml_providers saml_providers_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.saml_providers
    ADD CONSTRAINT saml_providers_pkey PRIMARY KEY (id);


--
-- Name: saml_relay_states saml_relay_states_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.saml_relay_states
    ADD CONSTRAINT saml_relay_states_pkey PRIMARY KEY (id);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);


--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);


--
-- Name: sso_domains sso_domains_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.sso_domains
    ADD CONSTRAINT sso_domains_pkey PRIMARY KEY (id);


--
-- Name: sso_providers sso_providers_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.sso_providers
    ADD CONSTRAINT sso_providers_pkey PRIMARY KEY (id);


--
-- Name: users users_phone_key; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.users
    ADD CONSTRAINT users_phone_key UNIQUE (phone);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: availability_calendar availability_calendar_equipment_id_date_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.availability_calendar
    ADD CONSTRAINT availability_calendar_equipment_id_date_key UNIQUE (equipment_id, date);


--
-- Name: availability_calendar availability_calendar_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.availability_calendar
    ADD CONSTRAINT availability_calendar_pkey PRIMARY KEY (id);


--
-- Name: booking_history booking_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.booking_history
    ADD CONSTRAINT booking_history_pkey PRIMARY KEY (id);


--
-- Name: booking_requests booking_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.booking_requests
    ADD CONSTRAINT booking_requests_pkey PRIMARY KEY (id);


--
-- Name: bookings bookings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bookings
    ADD CONSTRAINT bookings_pkey PRIMARY KEY (id);


--
-- Name: categories categories_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.categories
    ADD CONSTRAINT categories_pkey PRIMARY KEY (id);


--
-- Name: content_translations content_translations_content_type_content_id_field_name_tar_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.content_translations
    ADD CONSTRAINT content_translations_content_type_content_id_field_name_tar_key UNIQUE (content_type, content_id, field_name, target_lang);


--
-- Name: content_translations content_translations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.content_translations
    ADD CONSTRAINT content_translations_pkey PRIMARY KEY (id);


--
-- Name: conversation_participants conversation_participants_conversation_id_profile_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conversation_participants
    ADD CONSTRAINT conversation_participants_conversation_id_profile_id_key UNIQUE (conversation_id, profile_id);


--
-- Name: conversation_participants conversation_participants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conversation_participants
    ADD CONSTRAINT conversation_participants_pkey PRIMARY KEY (id);


--
-- Name: conversations conversations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conversations
    ADD CONSTRAINT conversations_pkey PRIMARY KEY (id);


--
-- Name: damage_claims damage_claims_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.damage_claims
    ADD CONSTRAINT damage_claims_pkey PRIMARY KEY (id);


--
-- Name: equipment_inspections equipment_inspections_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.equipment_inspections
    ADD CONSTRAINT equipment_inspections_pkey PRIMARY KEY (id);


--
-- Name: equipment_photos equipment_photos_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.equipment_photos
    ADD CONSTRAINT equipment_photos_pkey PRIMARY KEY (id);


--
-- Name: equipment equipment_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.equipment
    ADD CONSTRAINT equipment_pkey PRIMARY KEY (id);


--
-- Name: messages messages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_pkey PRIMARY KEY (id);


--
-- Name: notification_preferences notification_preferences_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_preferences
    ADD CONSTRAINT notification_preferences_pkey PRIMARY KEY (id);


--
-- Name: notification_preferences notification_preferences_user_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_preferences
    ADD CONSTRAINT notification_preferences_user_unique UNIQUE (user_id);


--
-- Name: notifications notifications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_pkey PRIMARY KEY (id);


--
-- Name: owner_profiles owner_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.owner_profiles
    ADD CONSTRAINT owner_profiles_pkey PRIMARY KEY (id);


--
-- Name: owner_profiles owner_profiles_profile_id_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.owner_profiles
    ADD CONSTRAINT owner_profiles_profile_id_unique UNIQUE (profile_id);


--
-- Name: payments payments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payments_pkey PRIMARY KEY (id);


--
-- Name: payments payments_stripe_payment_intent_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payments_stripe_payment_intent_id_key UNIQUE (stripe_payment_intent_id);


--
-- Name: profiles profiles_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.profiles
    ADD CONSTRAINT profiles_email_key UNIQUE (email);


--
-- Name: profiles profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.profiles
    ADD CONSTRAINT profiles_pkey PRIMARY KEY (id);


--
-- Name: rental_events rental_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rental_events
    ADD CONSTRAINT rental_events_pkey PRIMARY KEY (id);


--
-- Name: renter_profiles renter_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.renter_profiles
    ADD CONSTRAINT renter_profiles_pkey PRIMARY KEY (id);


--
-- Name: renter_profiles renter_profiles_profile_id_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.renter_profiles
    ADD CONSTRAINT renter_profiles_profile_id_unique UNIQUE (profile_id);


--
-- Name: reviews reviews_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reviews
    ADD CONSTRAINT reviews_pkey PRIMARY KEY (id);


--
-- Name: equipment_inspections unique_booking_inspection_type; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.equipment_inspections
    ADD CONSTRAINT unique_booking_inspection_type UNIQUE (booking_id, inspection_type);


--
-- Name: CONSTRAINT unique_booking_inspection_type ON equipment_inspections; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON CONSTRAINT unique_booking_inspection_type ON public.equipment_inspections IS 'Ensures only one inspection record per booking and inspection type (pickup or return)';


--
-- Name: bookings unique_booking_request; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bookings
    ADD CONSTRAINT unique_booking_request UNIQUE (booking_request_id);


--
-- Name: user_favorites user_favorites_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_favorites
    ADD CONSTRAINT user_favorites_pkey PRIMARY KEY (id);


--
-- Name: user_favorites user_favorites_user_id_equipment_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_favorites
    ADD CONSTRAINT user_favorites_user_id_equipment_id_key UNIQUE (user_id, equipment_id);


--
-- Name: user_verifications user_verifications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_verifications
    ADD CONSTRAINT user_verifications_pkey PRIMARY KEY (id);


--
-- Name: messages messages_pkey; Type: CONSTRAINT; Schema: realtime; Owner: -
--

ALTER TABLE ONLY realtime.messages
    ADD CONSTRAINT messages_pkey PRIMARY KEY (id, inserted_at);


--
-- Name: messages_2026_02_17 messages_2026_02_17_pkey; Type: CONSTRAINT; Schema: realtime; Owner: -
--

ALTER TABLE ONLY realtime.messages_2026_02_17
    ADD CONSTRAINT messages_2026_02_17_pkey PRIMARY KEY (id, inserted_at);


--
-- Name: messages_2026_02_18 messages_2026_02_18_pkey; Type: CONSTRAINT; Schema: realtime; Owner: -
--

ALTER TABLE ONLY realtime.messages_2026_02_18
    ADD CONSTRAINT messages_2026_02_18_pkey PRIMARY KEY (id, inserted_at);


--
-- Name: messages_2026_02_19 messages_2026_02_19_pkey; Type: CONSTRAINT; Schema: realtime; Owner: -
--

ALTER TABLE ONLY realtime.messages_2026_02_19
    ADD CONSTRAINT messages_2026_02_19_pkey PRIMARY KEY (id, inserted_at);


--
-- Name: messages_2026_02_20 messages_2026_02_20_pkey; Type: CONSTRAINT; Schema: realtime; Owner: -
--

ALTER TABLE ONLY realtime.messages_2026_02_20
    ADD CONSTRAINT messages_2026_02_20_pkey PRIMARY KEY (id, inserted_at);


--
-- Name: messages_2026_02_21 messages_2026_02_21_pkey; Type: CONSTRAINT; Schema: realtime; Owner: -
--

ALTER TABLE ONLY realtime.messages_2026_02_21
    ADD CONSTRAINT messages_2026_02_21_pkey PRIMARY KEY (id, inserted_at);


--
-- Name: messages_2026_02_22 messages_2026_02_22_pkey; Type: CONSTRAINT; Schema: realtime; Owner: -
--

ALTER TABLE ONLY realtime.messages_2026_02_22
    ADD CONSTRAINT messages_2026_02_22_pkey PRIMARY KEY (id, inserted_at);


--
-- Name: messages_2026_02_23 messages_2026_02_23_pkey; Type: CONSTRAINT; Schema: realtime; Owner: -
--

ALTER TABLE ONLY realtime.messages_2026_02_23
    ADD CONSTRAINT messages_2026_02_23_pkey PRIMARY KEY (id, inserted_at);


--
-- Name: subscription pk_subscription; Type: CONSTRAINT; Schema: realtime; Owner: -
--

ALTER TABLE ONLY realtime.subscription
    ADD CONSTRAINT pk_subscription PRIMARY KEY (id);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: realtime; Owner: -
--

ALTER TABLE ONLY realtime.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);


--
-- Name: buckets_analytics buckets_analytics_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.buckets_analytics
    ADD CONSTRAINT buckets_analytics_pkey PRIMARY KEY (id);


--
-- Name: buckets buckets_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.buckets
    ADD CONSTRAINT buckets_pkey PRIMARY KEY (id);


--
-- Name: buckets_vectors buckets_vectors_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.buckets_vectors
    ADD CONSTRAINT buckets_vectors_pkey PRIMARY KEY (id);


--
-- Name: migrations migrations_name_key; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.migrations
    ADD CONSTRAINT migrations_name_key UNIQUE (name);


--
-- Name: migrations migrations_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.migrations
    ADD CONSTRAINT migrations_pkey PRIMARY KEY (id);


--
-- Name: objects objects_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.objects
    ADD CONSTRAINT objects_pkey PRIMARY KEY (id);


--
-- Name: s3_multipart_uploads_parts s3_multipart_uploads_parts_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.s3_multipart_uploads_parts
    ADD CONSTRAINT s3_multipart_uploads_parts_pkey PRIMARY KEY (id);


--
-- Name: s3_multipart_uploads s3_multipart_uploads_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.s3_multipart_uploads
    ADD CONSTRAINT s3_multipart_uploads_pkey PRIMARY KEY (id);


--
-- Name: vector_indexes vector_indexes_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.vector_indexes
    ADD CONSTRAINT vector_indexes_pkey PRIMARY KEY (id);


--
-- Name: schema_migrations schema_migrations_idempotency_key_key; Type: CONSTRAINT; Schema: supabase_migrations; Owner: -
--

ALTER TABLE ONLY supabase_migrations.schema_migrations
    ADD CONSTRAINT schema_migrations_idempotency_key_key UNIQUE (idempotency_key);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: supabase_migrations; Owner: -
--

ALTER TABLE ONLY supabase_migrations.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);


--
-- Name: seed_files seed_files_pkey; Type: CONSTRAINT; Schema: supabase_migrations; Owner: -
--

ALTER TABLE ONLY supabase_migrations.seed_files
    ADD CONSTRAINT seed_files_pkey PRIMARY KEY (path);


--
-- Name: audit_logs_instance_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX audit_logs_instance_id_idx ON auth.audit_log_entries USING btree (instance_id);


--
-- Name: confirmation_token_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX confirmation_token_idx ON auth.users USING btree (confirmation_token) WHERE ((confirmation_token)::text !~ '^[0-9 ]*$'::text);


--
-- Name: email_change_token_current_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX email_change_token_current_idx ON auth.users USING btree (email_change_token_current) WHERE ((email_change_token_current)::text !~ '^[0-9 ]*$'::text);


--
-- Name: email_change_token_new_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX email_change_token_new_idx ON auth.users USING btree (email_change_token_new) WHERE ((email_change_token_new)::text !~ '^[0-9 ]*$'::text);


--
-- Name: factor_id_created_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX factor_id_created_at_idx ON auth.mfa_factors USING btree (user_id, created_at);


--
-- Name: flow_state_created_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX flow_state_created_at_idx ON auth.flow_state USING btree (created_at DESC);


--
-- Name: identities_email_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX identities_email_idx ON auth.identities USING btree (email text_pattern_ops);


--
-- Name: INDEX identities_email_idx; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON INDEX auth.identities_email_idx IS 'Auth: Ensures indexed queries on the email column';


--
-- Name: identities_user_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX identities_user_id_idx ON auth.identities USING btree (user_id);


--
-- Name: idx_auth_code; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX idx_auth_code ON auth.flow_state USING btree (auth_code);


--
-- Name: idx_oauth_client_states_created_at; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX idx_oauth_client_states_created_at ON auth.oauth_client_states USING btree (created_at);


--
-- Name: idx_user_id_auth_method; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX idx_user_id_auth_method ON auth.flow_state USING btree (user_id, authentication_method);


--
-- Name: mfa_challenge_created_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX mfa_challenge_created_at_idx ON auth.mfa_challenges USING btree (created_at DESC);


--
-- Name: mfa_factors_user_friendly_name_unique; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX mfa_factors_user_friendly_name_unique ON auth.mfa_factors USING btree (friendly_name, user_id) WHERE (TRIM(BOTH FROM friendly_name) <> ''::text);


--
-- Name: mfa_factors_user_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX mfa_factors_user_id_idx ON auth.mfa_factors USING btree (user_id);


--
-- Name: oauth_auth_pending_exp_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX oauth_auth_pending_exp_idx ON auth.oauth_authorizations USING btree (expires_at) WHERE (status = 'pending'::auth.oauth_authorization_status);


--
-- Name: oauth_clients_deleted_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX oauth_clients_deleted_at_idx ON auth.oauth_clients USING btree (deleted_at);


--
-- Name: oauth_consents_active_client_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX oauth_consents_active_client_idx ON auth.oauth_consents USING btree (client_id) WHERE (revoked_at IS NULL);


--
-- Name: oauth_consents_active_user_client_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX oauth_consents_active_user_client_idx ON auth.oauth_consents USING btree (user_id, client_id) WHERE (revoked_at IS NULL);


--
-- Name: oauth_consents_user_order_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX oauth_consents_user_order_idx ON auth.oauth_consents USING btree (user_id, granted_at DESC);


--
-- Name: one_time_tokens_relates_to_hash_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX one_time_tokens_relates_to_hash_idx ON auth.one_time_tokens USING hash (relates_to);


--
-- Name: one_time_tokens_token_hash_hash_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX one_time_tokens_token_hash_hash_idx ON auth.one_time_tokens USING hash (token_hash);


--
-- Name: one_time_tokens_user_id_token_type_key; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX one_time_tokens_user_id_token_type_key ON auth.one_time_tokens USING btree (user_id, token_type);


--
-- Name: reauthentication_token_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX reauthentication_token_idx ON auth.users USING btree (reauthentication_token) WHERE ((reauthentication_token)::text !~ '^[0-9 ]*$'::text);


--
-- Name: recovery_token_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX recovery_token_idx ON auth.users USING btree (recovery_token) WHERE ((recovery_token)::text !~ '^[0-9 ]*$'::text);


--
-- Name: refresh_tokens_instance_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX refresh_tokens_instance_id_idx ON auth.refresh_tokens USING btree (instance_id);


--
-- Name: refresh_tokens_instance_id_user_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX refresh_tokens_instance_id_user_id_idx ON auth.refresh_tokens USING btree (instance_id, user_id);


--
-- Name: refresh_tokens_parent_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX refresh_tokens_parent_idx ON auth.refresh_tokens USING btree (parent);


--
-- Name: refresh_tokens_session_id_revoked_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX refresh_tokens_session_id_revoked_idx ON auth.refresh_tokens USING btree (session_id, revoked);


--
-- Name: refresh_tokens_updated_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX refresh_tokens_updated_at_idx ON auth.refresh_tokens USING btree (updated_at DESC);


--
-- Name: saml_providers_sso_provider_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX saml_providers_sso_provider_id_idx ON auth.saml_providers USING btree (sso_provider_id);


--
-- Name: saml_relay_states_created_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX saml_relay_states_created_at_idx ON auth.saml_relay_states USING btree (created_at DESC);


--
-- Name: saml_relay_states_for_email_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX saml_relay_states_for_email_idx ON auth.saml_relay_states USING btree (for_email);


--
-- Name: saml_relay_states_sso_provider_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX saml_relay_states_sso_provider_id_idx ON auth.saml_relay_states USING btree (sso_provider_id);


--
-- Name: sessions_not_after_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX sessions_not_after_idx ON auth.sessions USING btree (not_after DESC);


--
-- Name: sessions_oauth_client_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX sessions_oauth_client_id_idx ON auth.sessions USING btree (oauth_client_id);


--
-- Name: sessions_user_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX sessions_user_id_idx ON auth.sessions USING btree (user_id);


--
-- Name: sso_domains_domain_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX sso_domains_domain_idx ON auth.sso_domains USING btree (lower(domain));


--
-- Name: sso_domains_sso_provider_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX sso_domains_sso_provider_id_idx ON auth.sso_domains USING btree (sso_provider_id);


--
-- Name: sso_providers_resource_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX sso_providers_resource_id_idx ON auth.sso_providers USING btree (lower(resource_id));


--
-- Name: sso_providers_resource_id_pattern_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX sso_providers_resource_id_pattern_idx ON auth.sso_providers USING btree (resource_id text_pattern_ops);


--
-- Name: unique_phone_factor_per_user; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX unique_phone_factor_per_user ON auth.mfa_factors USING btree (user_id, phone);


--
-- Name: user_id_created_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX user_id_created_at_idx ON auth.sessions USING btree (user_id, created_at);


--
-- Name: users_email_partial_key; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX users_email_partial_key ON auth.users USING btree (email) WHERE (is_sso_user = false);


--
-- Name: INDEX users_email_partial_key; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON INDEX auth.users_email_partial_key IS 'Auth: A partial unique index that applies only when is_sso_user is false';


--
-- Name: users_instance_id_email_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX users_instance_id_email_idx ON auth.users USING btree (instance_id, lower((email)::text));


--
-- Name: users_instance_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX users_instance_id_idx ON auth.users USING btree (instance_id);


--
-- Name: users_is_anonymous_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX users_is_anonymous_idx ON auth.users USING btree (is_anonymous);


--
-- Name: idx_availability_calendar_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_availability_calendar_created_at ON public.availability_calendar USING btree (created_at DESC);


--
-- Name: idx_availability_calendar_date; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_availability_calendar_date ON public.availability_calendar USING btree (date);


--
-- Name: idx_availability_calendar_equipment_date_range; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_availability_calendar_equipment_date_range ON public.availability_calendar USING btree (equipment_id, date);


--
-- Name: idx_availability_calendar_equipment_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_availability_calendar_equipment_id ON public.availability_calendar USING btree (equipment_id);


--
-- Name: idx_booking_history_booking_request_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_booking_history_booking_request_id ON public.booking_history USING btree (booking_request_id);


--
-- Name: idx_booking_history_changed_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_booking_history_changed_at ON public.booking_history USING btree (changed_at DESC);


--
-- Name: idx_booking_history_changed_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_booking_history_changed_by ON public.booking_history USING btree (changed_by);


--
-- Name: idx_booking_requests_conflict_check; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_booking_requests_conflict_check ON public.booking_requests USING btree (equipment_id, status, start_date, end_date) WHERE (status = ANY (ARRAY['pending'::public.booking_status, 'approved'::public.booking_status]));


--
-- Name: idx_booking_requests_created_at_desc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_booking_requests_created_at_desc ON public.booking_requests USING btree (created_at DESC);


--
-- Name: idx_booking_requests_equipment_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_booking_requests_equipment_id ON public.booking_requests USING btree (equipment_id);


--
-- Name: idx_booking_requests_equipment_status_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_booking_requests_equipment_status_created ON public.booking_requests USING btree (equipment_id, status, created_at DESC) WHERE (status = ANY (ARRAY['pending'::public.booking_status, 'approved'::public.booking_status, 'declined'::public.booking_status, 'cancelled'::public.booking_status]));


--
-- Name: idx_booking_requests_pending_cleanup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_booking_requests_pending_cleanup ON public.booking_requests USING btree (created_at) WHERE (status = 'pending'::public.booking_status);


--
-- Name: idx_booking_requests_renter_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_booking_requests_renter_id ON public.booking_requests USING btree (renter_id);


--
-- Name: idx_booking_requests_renter_status_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_booking_requests_renter_status_created ON public.booking_requests USING btree (renter_id, status, created_at DESC);


--
-- Name: idx_booking_requests_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_booking_requests_status ON public.booking_requests USING btree (status);


--
-- Name: idx_booking_requests_status_dates; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_booking_requests_status_dates ON public.booking_requests USING btree (status, start_date, end_date) WHERE (status = ANY (ARRAY['pending'::public.booking_status, 'approved'::public.booking_status]));


--
-- Name: idx_booking_requests_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_booking_requests_updated_at ON public.booking_requests USING btree (updated_at DESC);


--
-- Name: idx_bookings_booking_request_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_bookings_booking_request_id ON public.bookings USING btree (booking_request_id);


--
-- Name: idx_bookings_created_at_desc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_bookings_created_at_desc ON public.bookings USING btree (created_at DESC);


--
-- Name: idx_bookings_payment_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_bookings_payment_status ON public.bookings USING btree (payment_status);


--
-- Name: idx_bookings_return_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_bookings_return_status ON public.bookings USING btree (return_status);


--
-- Name: idx_bookings_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_bookings_updated_at ON public.bookings USING btree (updated_at DESC);


--
-- Name: idx_content_translations_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_content_translations_created_at ON public.content_translations USING btree (created_at);


--
-- Name: idx_content_translations_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_content_translations_lookup ON public.content_translations USING btree (content_type, content_id, target_lang);


--
-- Name: idx_conversation_participants_conversation_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_conversation_participants_conversation_id ON public.conversation_participants USING btree (conversation_id);


--
-- Name: idx_conversation_participants_last_read_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_conversation_participants_last_read_at ON public.conversation_participants USING btree (conversation_id, profile_id, last_read_at);


--
-- Name: idx_conversation_participants_profile_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_conversation_participants_profile_id ON public.conversation_participants USING btree (profile_id);


--
-- Name: idx_damage_claims_booking; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_damage_claims_booking ON public.damage_claims USING btree (booking_id);


--
-- Name: idx_damage_claims_filed_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_damage_claims_filed_by ON public.damage_claims USING btree (filed_by);


--
-- Name: idx_damage_claims_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_damage_claims_status ON public.damage_claims USING btree (status);


--
-- Name: idx_equipment_available; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_equipment_available ON public.equipment USING btree (is_available);


--
-- Name: idx_equipment_category_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_equipment_category_id ON public.equipment USING btree (category_id);


--
-- Name: idx_equipment_inspections_booking; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_equipment_inspections_booking ON public.equipment_inspections USING btree (booking_id);


--
-- Name: idx_equipment_inspections_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_equipment_inspections_type ON public.equipment_inspections USING btree (inspection_type);


--
-- Name: idx_equipment_location; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_equipment_location ON public.equipment USING gist (public.st_point((longitude)::double precision, (latitude)::double precision));


--
-- Name: idx_equipment_owner_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_equipment_owner_id ON public.equipment USING btree (owner_id);


--
-- Name: idx_equipment_photos_equipment_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_equipment_photos_equipment_id ON public.equipment_photos USING btree (equipment_id);


--
-- Name: idx_messages_conversation_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_messages_conversation_id ON public.messages USING btree (conversation_id);


--
-- Name: idx_messages_sender_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_messages_sender_id ON public.messages USING btree (sender_id);


--
-- Name: idx_notifications_actor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_notifications_actor ON public.notifications USING btree (actor_id) WHERE (actor_id IS NOT NULL);


--
-- Name: idx_notifications_archive_cleanup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_notifications_archive_cleanup ON public.notifications USING btree (created_at) WHERE (is_archived = true);


--
-- Name: idx_notifications_group_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_notifications_group_key ON public.notifications USING btree (user_id, group_key, created_at DESC) WHERE ((group_key IS NOT NULL) AND (NOT is_archived));


--
-- Name: idx_notifications_user_all; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_notifications_user_all ON public.notifications USING btree (user_id, created_at DESC) WHERE (NOT is_archived);


--
-- Name: idx_notifications_user_unread; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_notifications_user_unread ON public.notifications USING btree (user_id, created_at DESC) WHERE ((NOT is_archived) AND (NOT is_read));


--
-- Name: idx_owner_profiles_profile_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_owner_profiles_profile_id ON public.owner_profiles USING btree (profile_id);


--
-- Name: idx_payments_booking_request; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_payments_booking_request ON public.payments USING btree (booking_request_id);


--
-- Name: idx_payments_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_payments_created_at ON public.payments USING btree (created_at DESC);


--
-- Name: idx_payments_escrow_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_payments_escrow_status ON public.payments USING btree (escrow_status);


--
-- Name: idx_payments_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_payments_owner ON public.payments USING btree (owner_id);


--
-- Name: idx_payments_payout_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_payments_payout_status ON public.payments USING btree (payout_status);


--
-- Name: idx_payments_renter; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_payments_renter ON public.payments USING btree (renter_id);


--
-- Name: idx_payments_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_payments_status ON public.payments USING btree (payment_status);


--
-- Name: idx_payments_status_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_payments_status_created_at ON public.payments USING btree (payment_status, created_at DESC);


--
-- Name: idx_profiles_last_seen_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_profiles_last_seen_at ON public.profiles USING btree (last_seen_at);


--
-- Name: idx_profiles_trust_score; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_profiles_trust_score ON public.profiles USING btree (trust_score);


--
-- Name: idx_profiles_verification_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_profiles_verification_status ON public.profiles USING btree (identity_verified, phone_verified, email_verified, address_verified) WHERE ((identity_verified = true) OR (phone_verified = true) OR (email_verified = true) OR (address_verified = true));


--
-- Name: idx_rental_events_booking; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_rental_events_booking ON public.rental_events USING btree (booking_id);


--
-- Name: idx_rental_events_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_rental_events_type ON public.rental_events USING btree (event_type);


--
-- Name: idx_renter_profiles_profile_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_renter_profiles_profile_id ON public.renter_profiles USING btree (profile_id);


--
-- Name: idx_reviews_booking_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reviews_booking_id ON public.reviews USING btree (booking_id);


--
-- Name: idx_reviews_reviewee_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reviews_reviewee_id ON public.reviews USING btree (reviewee_id);


--
-- Name: idx_reviews_reviewer_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reviews_reviewer_id ON public.reviews USING btree (reviewer_id);


--
-- Name: idx_user_favorites_equipment_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_favorites_equipment_id ON public.user_favorites USING btree (equipment_id);


--
-- Name: idx_user_favorites_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_favorites_user_id ON public.user_favorites USING btree (user_id);


--
-- Name: idx_user_verifications_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_verifications_user_id ON public.user_verifications USING btree (user_id);


--
-- Name: messages_conversation_id_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_conversation_id_created_at_idx ON public.messages USING btree (conversation_id, created_at);


--
-- Name: idx_realtime_messages_topic; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX idx_realtime_messages_topic ON ONLY realtime.messages USING btree (topic);


--
-- Name: ix_realtime_subscription_entity; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX ix_realtime_subscription_entity ON realtime.subscription USING btree (entity);


--
-- Name: messages_inserted_at_topic_index; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX messages_inserted_at_topic_index ON ONLY realtime.messages USING btree (inserted_at DESC, topic) WHERE ((extension = 'broadcast'::text) AND (private IS TRUE));


--
-- Name: messages_2026_02_17_inserted_at_topic_idx; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX messages_2026_02_17_inserted_at_topic_idx ON realtime.messages_2026_02_17 USING btree (inserted_at DESC, topic) WHERE ((extension = 'broadcast'::text) AND (private IS TRUE));


--
-- Name: messages_2026_02_17_topic_idx; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX messages_2026_02_17_topic_idx ON realtime.messages_2026_02_17 USING btree (topic);


--
-- Name: messages_2026_02_18_inserted_at_topic_idx; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX messages_2026_02_18_inserted_at_topic_idx ON realtime.messages_2026_02_18 USING btree (inserted_at DESC, topic) WHERE ((extension = 'broadcast'::text) AND (private IS TRUE));


--
-- Name: messages_2026_02_18_topic_idx; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX messages_2026_02_18_topic_idx ON realtime.messages_2026_02_18 USING btree (topic);


--
-- Name: messages_2026_02_19_inserted_at_topic_idx; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX messages_2026_02_19_inserted_at_topic_idx ON realtime.messages_2026_02_19 USING btree (inserted_at DESC, topic) WHERE ((extension = 'broadcast'::text) AND (private IS TRUE));


--
-- Name: messages_2026_02_19_topic_idx; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX messages_2026_02_19_topic_idx ON realtime.messages_2026_02_19 USING btree (topic);


--
-- Name: messages_2026_02_20_inserted_at_topic_idx; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX messages_2026_02_20_inserted_at_topic_idx ON realtime.messages_2026_02_20 USING btree (inserted_at DESC, topic) WHERE ((extension = 'broadcast'::text) AND (private IS TRUE));


--
-- Name: messages_2026_02_20_topic_idx; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX messages_2026_02_20_topic_idx ON realtime.messages_2026_02_20 USING btree (topic);


--
-- Name: messages_2026_02_21_inserted_at_topic_idx; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX messages_2026_02_21_inserted_at_topic_idx ON realtime.messages_2026_02_21 USING btree (inserted_at DESC, topic) WHERE ((extension = 'broadcast'::text) AND (private IS TRUE));


--
-- Name: messages_2026_02_21_topic_idx; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX messages_2026_02_21_topic_idx ON realtime.messages_2026_02_21 USING btree (topic);


--
-- Name: messages_2026_02_22_inserted_at_topic_idx; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX messages_2026_02_22_inserted_at_topic_idx ON realtime.messages_2026_02_22 USING btree (inserted_at DESC, topic) WHERE ((extension = 'broadcast'::text) AND (private IS TRUE));


--
-- Name: messages_2026_02_22_topic_idx; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX messages_2026_02_22_topic_idx ON realtime.messages_2026_02_22 USING btree (topic);


--
-- Name: messages_2026_02_23_inserted_at_topic_idx; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX messages_2026_02_23_inserted_at_topic_idx ON realtime.messages_2026_02_23 USING btree (inserted_at DESC, topic) WHERE ((extension = 'broadcast'::text) AND (private IS TRUE));


--
-- Name: messages_2026_02_23_topic_idx; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX messages_2026_02_23_topic_idx ON realtime.messages_2026_02_23 USING btree (topic);


--
-- Name: subscription_subscription_id_entity_filters_action_filter_key; Type: INDEX; Schema: realtime; Owner: -
--

CREATE UNIQUE INDEX subscription_subscription_id_entity_filters_action_filter_key ON realtime.subscription USING btree (subscription_id, entity, filters, action_filter);


--
-- Name: bname; Type: INDEX; Schema: storage; Owner: -
--

CREATE UNIQUE INDEX bname ON storage.buckets USING btree (name);


--
-- Name: bucketid_objname; Type: INDEX; Schema: storage; Owner: -
--

CREATE UNIQUE INDEX bucketid_objname ON storage.objects USING btree (bucket_id, name);


--
-- Name: buckets_analytics_unique_name_idx; Type: INDEX; Schema: storage; Owner: -
--

CREATE UNIQUE INDEX buckets_analytics_unique_name_idx ON storage.buckets_analytics USING btree (name) WHERE (deleted_at IS NULL);


--
-- Name: idx_multipart_uploads_list; Type: INDEX; Schema: storage; Owner: -
--

CREATE INDEX idx_multipart_uploads_list ON storage.s3_multipart_uploads USING btree (bucket_id, key, created_at);


--
-- Name: idx_objects_bucket_id_name; Type: INDEX; Schema: storage; Owner: -
--

CREATE INDEX idx_objects_bucket_id_name ON storage.objects USING btree (bucket_id, name COLLATE "C");


--
-- Name: idx_objects_bucket_id_name_lower; Type: INDEX; Schema: storage; Owner: -
--

CREATE INDEX idx_objects_bucket_id_name_lower ON storage.objects USING btree (bucket_id, lower(name) COLLATE "C");


--
-- Name: name_prefix_search; Type: INDEX; Schema: storage; Owner: -
--

CREATE INDEX name_prefix_search ON storage.objects USING btree (name text_pattern_ops);


--
-- Name: vector_indexes_name_bucket_id_idx; Type: INDEX; Schema: storage; Owner: -
--

CREATE UNIQUE INDEX vector_indexes_name_bucket_id_idx ON storage.vector_indexes USING btree (name, bucket_id);


--
-- Name: messages_2026_02_17_inserted_at_topic_idx; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX realtime.messages_inserted_at_topic_index ATTACH PARTITION realtime.messages_2026_02_17_inserted_at_topic_idx;


--
-- Name: messages_2026_02_17_pkey; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX realtime.messages_pkey ATTACH PARTITION realtime.messages_2026_02_17_pkey;


--
-- Name: messages_2026_02_17_topic_idx; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX realtime.idx_realtime_messages_topic ATTACH PARTITION realtime.messages_2026_02_17_topic_idx;


--
-- Name: messages_2026_02_18_inserted_at_topic_idx; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX realtime.messages_inserted_at_topic_index ATTACH PARTITION realtime.messages_2026_02_18_inserted_at_topic_idx;


--
-- Name: messages_2026_02_18_pkey; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX realtime.messages_pkey ATTACH PARTITION realtime.messages_2026_02_18_pkey;


--
-- Name: messages_2026_02_18_topic_idx; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX realtime.idx_realtime_messages_topic ATTACH PARTITION realtime.messages_2026_02_18_topic_idx;


--
-- Name: messages_2026_02_19_inserted_at_topic_idx; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX realtime.messages_inserted_at_topic_index ATTACH PARTITION realtime.messages_2026_02_19_inserted_at_topic_idx;


--
-- Name: messages_2026_02_19_pkey; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX realtime.messages_pkey ATTACH PARTITION realtime.messages_2026_02_19_pkey;


--
-- Name: messages_2026_02_19_topic_idx; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX realtime.idx_realtime_messages_topic ATTACH PARTITION realtime.messages_2026_02_19_topic_idx;


--
-- Name: messages_2026_02_20_inserted_at_topic_idx; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX realtime.messages_inserted_at_topic_index ATTACH PARTITION realtime.messages_2026_02_20_inserted_at_topic_idx;


--
-- Name: messages_2026_02_20_pkey; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX realtime.messages_pkey ATTACH PARTITION realtime.messages_2026_02_20_pkey;


--
-- Name: messages_2026_02_20_topic_idx; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX realtime.idx_realtime_messages_topic ATTACH PARTITION realtime.messages_2026_02_20_topic_idx;


--
-- Name: messages_2026_02_21_inserted_at_topic_idx; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX realtime.messages_inserted_at_topic_index ATTACH PARTITION realtime.messages_2026_02_21_inserted_at_topic_idx;


--
-- Name: messages_2026_02_21_pkey; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX realtime.messages_pkey ATTACH PARTITION realtime.messages_2026_02_21_pkey;


--
-- Name: messages_2026_02_21_topic_idx; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX realtime.idx_realtime_messages_topic ATTACH PARTITION realtime.messages_2026_02_21_topic_idx;


--
-- Name: messages_2026_02_22_inserted_at_topic_idx; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX realtime.messages_inserted_at_topic_index ATTACH PARTITION realtime.messages_2026_02_22_inserted_at_topic_idx;


--
-- Name: messages_2026_02_22_pkey; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX realtime.messages_pkey ATTACH PARTITION realtime.messages_2026_02_22_pkey;


--
-- Name: messages_2026_02_22_topic_idx; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX realtime.idx_realtime_messages_topic ATTACH PARTITION realtime.messages_2026_02_22_topic_idx;


--
-- Name: messages_2026_02_23_inserted_at_topic_idx; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX realtime.messages_inserted_at_topic_index ATTACH PARTITION realtime.messages_2026_02_23_inserted_at_topic_idx;


--
-- Name: messages_2026_02_23_pkey; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX realtime.messages_pkey ATTACH PARTITION realtime.messages_2026_02_23_pkey;


--
-- Name: messages_2026_02_23_topic_idx; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX realtime.idx_realtime_messages_topic ATTACH PARTITION realtime.messages_2026_02_23_topic_idx;


--
-- Name: users on_auth_user_created; Type: TRIGGER; Schema: auth; Owner: -
--

CREATE TRIGGER on_auth_user_created AFTER INSERT ON auth.users FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();


--
-- Name: booking_requests booking_status_transition_check; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER booking_status_transition_check BEFORE UPDATE OF status ON public.booking_requests FOR EACH ROW EXECUTE FUNCTION public.validate_booking_status_transition();


--
-- Name: notification_preferences notification_preferences_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER notification_preferences_updated_at BEFORE UPDATE ON public.notification_preferences FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: conversation_participants notify_conversation_participant_added_trg; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER notify_conversation_participant_added_trg AFTER INSERT ON public.conversation_participants FOR EACH ROW EXECUTE FUNCTION public.notify_conversation_participant_added();


--
-- Name: messages notify_message_created_trg; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER notify_message_created_trg AFTER INSERT ON public.messages FOR EACH ROW EXECUTE FUNCTION public.notify_message_created();


--
-- Name: bookings on_booking_created_notify; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER on_booking_created_notify AFTER INSERT ON public.bookings FOR EACH ROW EXECUTE FUNCTION public.notify_on_booking_created();


--
-- Name: booking_requests on_booking_request_cancelled_notify; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER on_booking_request_cancelled_notify AFTER UPDATE ON public.booking_requests FOR EACH ROW EXECUTE FUNCTION public.notify_on_booking_request_cancelled();


--
-- Name: bookings on_booking_status_change_notify; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER on_booking_status_change_notify AFTER UPDATE ON public.bookings FOR EACH ROW EXECUTE FUNCTION public.notify_on_booking_status_change();


--
-- Name: user_favorites on_equipment_favorited_notify; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER on_equipment_favorited_notify AFTER INSERT ON public.user_favorites FOR EACH ROW EXECUTE FUNCTION public.notify_on_equipment_favorited();


--
-- Name: messages on_new_message_notify; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER on_new_message_notify AFTER INSERT ON public.messages FOR EACH ROW EXECUTE FUNCTION public.notify_on_new_message();


--
-- Name: reviews on_new_review_notify; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER on_new_review_notify AFTER INSERT ON public.reviews FOR EACH ROW EXECUTE FUNCTION public.notify_on_new_review();


--
-- Name: payments on_payout_notify; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER on_payout_notify AFTER UPDATE ON public.payments FOR EACH ROW EXECUTE FUNCTION public.notify_on_payout();


--
-- Name: profiles on_profile_created_create_notification_preferences; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER on_profile_created_create_notification_preferences AFTER INSERT ON public.profiles FOR EACH ROW EXECUTE FUNCTION public.create_default_notification_preferences();


--
-- Name: payments on_refund_notify; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER on_refund_notify AFTER UPDATE ON public.payments FOR EACH ROW EXECUTE FUNCTION public.notify_on_refund();


--
-- Name: user_verifications on_verification_submitted_notify; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER on_verification_submitted_notify AFTER INSERT OR UPDATE ON public.user_verifications FOR EACH ROW EXECUTE FUNCTION public.notify_admins_on_verification_submitted();


--
-- Name: payments payments_updated_at_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER payments_updated_at_trigger BEFORE UPDATE ON public.payments FOR EACH ROW EXECUTE FUNCTION public.update_payments_updated_at();


--
-- Name: profiles prevent_role_escalation_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER prevent_role_escalation_trigger BEFORE UPDATE ON public.profiles FOR EACH ROW WHEN ((old.role IS DISTINCT FROM new.role)) EXECUTE FUNCTION public.prevent_role_escalation();


--
-- Name: profiles protect_profiles_sensitive_fields; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER protect_profiles_sensitive_fields BEFORE UPDATE ON public.profiles FOR EACH ROW EXECUTE FUNCTION public.protect_profiles_sensitive_fields();


--
-- Name: messages response_time_message_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER response_time_message_trigger AFTER INSERT ON public.messages FOR EACH ROW EXECUTE FUNCTION public.trigger_update_response_time_on_message();


--
-- Name: content_translations set_content_translations_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_content_translations_updated_at BEFORE UPDATE ON public.content_translations FOR EACH ROW EXECUTE FUNCTION public.update_content_translations_updated_at();


--
-- Name: conversation_participants trg_conversation_read_last_seen; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_conversation_read_last_seen AFTER UPDATE OF last_read_at ON public.conversation_participants FOR EACH ROW WHEN (((new.last_read_at IS NOT NULL) AND (new.last_read_at IS DISTINCT FROM old.last_read_at))) EXECUTE FUNCTION public.touch_last_seen_on_conversation_read();


--
-- Name: messages trg_messages_last_seen; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_messages_last_seen AFTER INSERT ON public.messages FOR EACH ROW EXECUTE FUNCTION public.touch_last_seen_on_message();


--
-- Name: booking_requests trigger_booking_approval; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_booking_approval AFTER UPDATE OF status ON public.booking_requests FOR EACH ROW WHEN (((new.status = 'approved'::public.booking_status) AND (old.status <> 'approved'::public.booking_status))) EXECUTE FUNCTION public.handle_booking_approval();


--
-- Name: booking_requests trigger_booking_cancellation; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_booking_cancellation AFTER UPDATE OF status ON public.booking_requests FOR EACH ROW WHEN ((((new.status = 'declined'::public.booking_status) OR (new.status = 'cancelled'::public.booking_status)) AND (old.status = 'approved'::public.booking_status))) EXECUTE FUNCTION public.handle_booking_cancellation();


--
-- Name: booking_requests trigger_booking_completion; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_booking_completion AFTER UPDATE OF status ON public.booking_requests FOR EACH ROW WHEN ((((new.status)::text = 'completed'::text) AND ((old.status IS NULL) OR ((old.status)::text <> 'completed'::text)))) EXECUTE FUNCTION public.handle_booking_completion();


--
-- Name: booking_requests trigger_booking_initial_approval; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_booking_initial_approval AFTER INSERT ON public.booking_requests FOR EACH ROW WHEN ((new.status = 'approved'::public.booking_status)) EXECUTE FUNCTION public.handle_booking_approval();


--
-- Name: booking_requests trigger_log_booking_status_change; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_log_booking_status_change AFTER UPDATE OF status ON public.booking_requests FOR EACH ROW WHEN ((new.status IS DISTINCT FROM old.status)) EXECUTE FUNCTION public.log_booking_status_change();


--
-- Name: payments trigger_set_payout_processed_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_set_payout_processed_at BEFORE UPDATE ON public.payments FOR EACH ROW EXECUTE FUNCTION public.set_payout_processed_at();


--
-- Name: payments trigger_sync_payment_status; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_sync_payment_status AFTER INSERT OR UPDATE OF payment_status ON public.payments FOR EACH ROW EXECUTE FUNCTION public.sync_payment_status_to_booking();


--
-- Name: profiles trigger_sync_profile_from_auth; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_sync_profile_from_auth BEFORE INSERT ON public.profiles FOR EACH ROW EXECUTE FUNCTION public.sync_profile_from_auth();


--
-- Name: damage_claims trigger_update_damage_claims_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_update_damage_claims_updated_at BEFORE UPDATE ON public.damage_claims FOR EACH ROW EXECUTE FUNCTION public.update_damage_claims_updated_at();


--
-- Name: booking_requests trust_score_booking_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trust_score_booking_trigger AFTER UPDATE OF status ON public.booking_requests FOR EACH ROW EXECUTE FUNCTION public.trigger_update_trust_score_on_booking_complete();


--
-- Name: reviews trust_score_review_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trust_score_review_trigger AFTER INSERT ON public.reviews FOR EACH ROW EXECUTE FUNCTION public.trigger_update_trust_score_on_review();


--
-- Name: profiles trust_score_verification_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trust_score_verification_trigger AFTER UPDATE OF identity_verified, phone_verified, email_verified, address_verified ON public.profiles FOR EACH ROW EXECUTE FUNCTION public.trigger_update_trust_score_on_verification();


--
-- Name: booking_requests update_booking_requests_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_booking_requests_updated_at BEFORE UPDATE ON public.booking_requests FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: bookings update_bookings_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_bookings_updated_at BEFORE UPDATE ON public.bookings FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: categories update_categories_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_categories_updated_at BEFORE UPDATE ON public.categories FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: conversations update_conversations_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_conversations_updated_at BEFORE UPDATE ON public.conversations FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: equipment update_equipment_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_equipment_updated_at BEFORE UPDATE ON public.equipment FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: owner_profiles update_owner_profiles_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_owner_profiles_updated_at BEFORE UPDATE ON public.owner_profiles FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: profiles update_profiles_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_profiles_updated_at BEFORE UPDATE ON public.profiles FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: renter_profiles update_renter_profiles_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_renter_profiles_updated_at BEFORE UPDATE ON public.renter_profiles FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: subscription tr_check_filters; Type: TRIGGER; Schema: realtime; Owner: -
--

CREATE TRIGGER tr_check_filters BEFORE INSERT OR UPDATE ON realtime.subscription FOR EACH ROW EXECUTE FUNCTION realtime.subscription_check_filters();


--
-- Name: buckets enforce_bucket_name_length_trigger; Type: TRIGGER; Schema: storage; Owner: -
--

CREATE TRIGGER enforce_bucket_name_length_trigger BEFORE INSERT OR UPDATE OF name ON storage.buckets FOR EACH ROW EXECUTE FUNCTION storage.enforce_bucket_name_length();


--
-- Name: buckets protect_buckets_delete; Type: TRIGGER; Schema: storage; Owner: -
--

CREATE TRIGGER protect_buckets_delete BEFORE DELETE ON storage.buckets FOR EACH STATEMENT EXECUTE FUNCTION storage.protect_delete();


--
-- Name: objects protect_objects_delete; Type: TRIGGER; Schema: storage; Owner: -
--

CREATE TRIGGER protect_objects_delete BEFORE DELETE ON storage.objects FOR EACH STATEMENT EXECUTE FUNCTION storage.protect_delete();


--
-- Name: objects update_objects_updated_at; Type: TRIGGER; Schema: storage; Owner: -
--

CREATE TRIGGER update_objects_updated_at BEFORE UPDATE ON storage.objects FOR EACH ROW EXECUTE FUNCTION storage.update_updated_at_column();


--
-- Name: identities identities_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.identities
    ADD CONSTRAINT identities_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: mfa_amr_claims mfa_amr_claims_session_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_amr_claims
    ADD CONSTRAINT mfa_amr_claims_session_id_fkey FOREIGN KEY (session_id) REFERENCES auth.sessions(id) ON DELETE CASCADE;


--
-- Name: mfa_challenges mfa_challenges_auth_factor_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_challenges
    ADD CONSTRAINT mfa_challenges_auth_factor_id_fkey FOREIGN KEY (factor_id) REFERENCES auth.mfa_factors(id) ON DELETE CASCADE;


--
-- Name: mfa_factors mfa_factors_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_factors
    ADD CONSTRAINT mfa_factors_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: oauth_authorizations oauth_authorizations_client_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oauth_authorizations
    ADD CONSTRAINT oauth_authorizations_client_id_fkey FOREIGN KEY (client_id) REFERENCES auth.oauth_clients(id) ON DELETE CASCADE;


--
-- Name: oauth_authorizations oauth_authorizations_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oauth_authorizations
    ADD CONSTRAINT oauth_authorizations_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: oauth_consents oauth_consents_client_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oauth_consents
    ADD CONSTRAINT oauth_consents_client_id_fkey FOREIGN KEY (client_id) REFERENCES auth.oauth_clients(id) ON DELETE CASCADE;


--
-- Name: oauth_consents oauth_consents_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oauth_consents
    ADD CONSTRAINT oauth_consents_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: one_time_tokens one_time_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.one_time_tokens
    ADD CONSTRAINT one_time_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: refresh_tokens refresh_tokens_session_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.refresh_tokens
    ADD CONSTRAINT refresh_tokens_session_id_fkey FOREIGN KEY (session_id) REFERENCES auth.sessions(id) ON DELETE CASCADE;


--
-- Name: saml_providers saml_providers_sso_provider_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.saml_providers
    ADD CONSTRAINT saml_providers_sso_provider_id_fkey FOREIGN KEY (sso_provider_id) REFERENCES auth.sso_providers(id) ON DELETE CASCADE;


--
-- Name: saml_relay_states saml_relay_states_flow_state_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.saml_relay_states
    ADD CONSTRAINT saml_relay_states_flow_state_id_fkey FOREIGN KEY (flow_state_id) REFERENCES auth.flow_state(id) ON DELETE CASCADE;


--
-- Name: saml_relay_states saml_relay_states_sso_provider_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.saml_relay_states
    ADD CONSTRAINT saml_relay_states_sso_provider_id_fkey FOREIGN KEY (sso_provider_id) REFERENCES auth.sso_providers(id) ON DELETE CASCADE;


--
-- Name: sessions sessions_oauth_client_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.sessions
    ADD CONSTRAINT sessions_oauth_client_id_fkey FOREIGN KEY (oauth_client_id) REFERENCES auth.oauth_clients(id) ON DELETE CASCADE;


--
-- Name: sessions sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.sessions
    ADD CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: sso_domains sso_domains_sso_provider_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.sso_domains
    ADD CONSTRAINT sso_domains_sso_provider_id_fkey FOREIGN KEY (sso_provider_id) REFERENCES auth.sso_providers(id) ON DELETE CASCADE;


--
-- Name: availability_calendar availability_calendar_equipment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.availability_calendar
    ADD CONSTRAINT availability_calendar_equipment_id_fkey FOREIGN KEY (equipment_id) REFERENCES public.equipment(id) ON DELETE CASCADE;


--
-- Name: booking_history booking_history_booking_request_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.booking_history
    ADD CONSTRAINT booking_history_booking_request_id_fkey FOREIGN KEY (booking_request_id) REFERENCES public.booking_requests(id) ON DELETE CASCADE;


--
-- Name: booking_history booking_history_changed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.booking_history
    ADD CONSTRAINT booking_history_changed_by_fkey FOREIGN KEY (changed_by) REFERENCES public.profiles(id) ON DELETE SET NULL;


--
-- Name: booking_requests booking_requests_equipment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.booking_requests
    ADD CONSTRAINT booking_requests_equipment_id_fkey FOREIGN KEY (equipment_id) REFERENCES public.equipment(id) ON DELETE CASCADE;


--
-- Name: booking_requests booking_requests_renter_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.booking_requests
    ADD CONSTRAINT booking_requests_renter_id_fkey FOREIGN KEY (renter_id) REFERENCES public.profiles(id) ON DELETE CASCADE;


--
-- Name: bookings bookings_booking_request_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bookings
    ADD CONSTRAINT bookings_booking_request_id_fkey FOREIGN KEY (booking_request_id) REFERENCES public.booking_requests(id) ON DELETE CASCADE;


--
-- Name: categories categories_parent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.categories
    ADD CONSTRAINT categories_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES public.categories(id) ON DELETE SET NULL;


--
-- Name: conversation_participants conversation_participants_conversation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conversation_participants
    ADD CONSTRAINT conversation_participants_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.conversations(id) ON DELETE CASCADE;


--
-- Name: conversation_participants conversation_participants_profile_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conversation_participants
    ADD CONSTRAINT conversation_participants_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.profiles(id) ON DELETE CASCADE;


--
-- Name: conversations conversations_booking_request_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conversations
    ADD CONSTRAINT conversations_booking_request_id_fkey FOREIGN KEY (booking_request_id) REFERENCES public.booking_requests(id) ON DELETE CASCADE;


--
-- Name: damage_claims damage_claims_booking_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.damage_claims
    ADD CONSTRAINT damage_claims_booking_id_fkey FOREIGN KEY (booking_id) REFERENCES public.booking_requests(id) ON DELETE CASCADE;


--
-- Name: damage_claims damage_claims_filed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.damage_claims
    ADD CONSTRAINT damage_claims_filed_by_fkey FOREIGN KEY (filed_by) REFERENCES public.profiles(id);


--
-- Name: equipment equipment_category_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.equipment
    ADD CONSTRAINT equipment_category_id_fkey FOREIGN KEY (category_id) REFERENCES public.categories(id) ON DELETE RESTRICT;


--
-- Name: equipment_inspections equipment_inspections_booking_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.equipment_inspections
    ADD CONSTRAINT equipment_inspections_booking_id_fkey FOREIGN KEY (booking_id) REFERENCES public.booking_requests(id) ON DELETE CASCADE;


--
-- Name: equipment equipment_owner_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.equipment
    ADD CONSTRAINT equipment_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES public.profiles(id) ON DELETE CASCADE;


--
-- Name: equipment_photos equipment_photos_equipment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.equipment_photos
    ADD CONSTRAINT equipment_photos_equipment_id_fkey FOREIGN KEY (equipment_id) REFERENCES public.equipment(id) ON DELETE CASCADE;


--
-- Name: messages messages_conversation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.conversations(id) ON DELETE CASCADE;


--
-- Name: messages messages_sender_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_sender_id_fkey FOREIGN KEY (sender_id) REFERENCES public.profiles(id) ON DELETE CASCADE;


--
-- Name: notification_preferences notification_preferences_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_preferences
    ADD CONSTRAINT notification_preferences_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.profiles(id) ON DELETE CASCADE;


--
-- Name: notifications notifications_actor_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_actor_id_fkey FOREIGN KEY (actor_id) REFERENCES public.profiles(id) ON DELETE SET NULL;


--
-- Name: notifications notifications_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.profiles(id) ON DELETE CASCADE;


--
-- Name: owner_profiles owner_profiles_profile_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.owner_profiles
    ADD CONSTRAINT owner_profiles_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.profiles(id) ON DELETE CASCADE;


--
-- Name: payments payments_booking_request_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payments_booking_request_id_fkey FOREIGN KEY (booking_request_id) REFERENCES public.booking_requests(id) ON DELETE CASCADE;


--
-- Name: payments payments_owner_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payments_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES public.profiles(id) ON DELETE CASCADE;


--
-- Name: payments payments_renter_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payments_renter_id_fkey FOREIGN KEY (renter_id) REFERENCES public.profiles(id) ON DELETE CASCADE;


--
-- Name: rental_events rental_events_booking_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rental_events
    ADD CONSTRAINT rental_events_booking_id_fkey FOREIGN KEY (booking_id) REFERENCES public.booking_requests(id) ON DELETE CASCADE;


--
-- Name: rental_events rental_events_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rental_events
    ADD CONSTRAINT rental_events_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.profiles(id);


--
-- Name: renter_profiles renter_profiles_profile_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.renter_profiles
    ADD CONSTRAINT renter_profiles_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.profiles(id) ON DELETE CASCADE;


--
-- Name: reviews reviews_booking_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reviews
    ADD CONSTRAINT reviews_booking_id_fkey FOREIGN KEY (booking_id) REFERENCES public.booking_requests(id) ON DELETE CASCADE;


--
-- Name: reviews reviews_reviewee_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reviews
    ADD CONSTRAINT reviews_reviewee_id_fkey FOREIGN KEY (reviewee_id) REFERENCES public.profiles(id) ON DELETE CASCADE;


--
-- Name: reviews reviews_reviewer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reviews
    ADD CONSTRAINT reviews_reviewer_id_fkey FOREIGN KEY (reviewer_id) REFERENCES public.profiles(id) ON DELETE CASCADE;


--
-- Name: user_favorites user_favorites_equipment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_favorites
    ADD CONSTRAINT user_favorites_equipment_id_fkey FOREIGN KEY (equipment_id) REFERENCES public.equipment(id) ON DELETE CASCADE;


--
-- Name: user_favorites user_favorites_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_favorites
    ADD CONSTRAINT user_favorites_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.profiles(id) ON DELETE CASCADE;


--
-- Name: user_verifications user_verifications_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_verifications
    ADD CONSTRAINT user_verifications_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.profiles(id) ON DELETE CASCADE;


--
-- Name: objects objects_bucketId_fkey; Type: FK CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.objects
    ADD CONSTRAINT "objects_bucketId_fkey" FOREIGN KEY (bucket_id) REFERENCES storage.buckets(id);


--
-- Name: s3_multipart_uploads s3_multipart_uploads_bucket_id_fkey; Type: FK CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.s3_multipart_uploads
    ADD CONSTRAINT s3_multipart_uploads_bucket_id_fkey FOREIGN KEY (bucket_id) REFERENCES storage.buckets(id);


--
-- Name: s3_multipart_uploads_parts s3_multipart_uploads_parts_bucket_id_fkey; Type: FK CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.s3_multipart_uploads_parts
    ADD CONSTRAINT s3_multipart_uploads_parts_bucket_id_fkey FOREIGN KEY (bucket_id) REFERENCES storage.buckets(id);


--
-- Name: s3_multipart_uploads_parts s3_multipart_uploads_parts_upload_id_fkey; Type: FK CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.s3_multipart_uploads_parts
    ADD CONSTRAINT s3_multipart_uploads_parts_upload_id_fkey FOREIGN KEY (upload_id) REFERENCES storage.s3_multipart_uploads(id) ON DELETE CASCADE;


--
-- Name: vector_indexes vector_indexes_bucket_id_fkey; Type: FK CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.vector_indexes
    ADD CONSTRAINT vector_indexes_bucket_id_fkey FOREIGN KEY (bucket_id) REFERENCES storage.buckets_vectors(id);


--
-- Name: audit_log_entries; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.audit_log_entries ENABLE ROW LEVEL SECURITY;

--
-- Name: flow_state; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.flow_state ENABLE ROW LEVEL SECURITY;

--
-- Name: identities; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.identities ENABLE ROW LEVEL SECURITY;

--
-- Name: instances; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.instances ENABLE ROW LEVEL SECURITY;

--
-- Name: mfa_amr_claims; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.mfa_amr_claims ENABLE ROW LEVEL SECURITY;

--
-- Name: mfa_challenges; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.mfa_challenges ENABLE ROW LEVEL SECURITY;

--
-- Name: mfa_factors; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.mfa_factors ENABLE ROW LEVEL SECURITY;

--
-- Name: one_time_tokens; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.one_time_tokens ENABLE ROW LEVEL SECURITY;

--
-- Name: refresh_tokens; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.refresh_tokens ENABLE ROW LEVEL SECURITY;

--
-- Name: saml_providers; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.saml_providers ENABLE ROW LEVEL SECURITY;

--
-- Name: saml_relay_states; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.saml_relay_states ENABLE ROW LEVEL SECURITY;

--
-- Name: schema_migrations; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.schema_migrations ENABLE ROW LEVEL SECURITY;

--
-- Name: sessions; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.sessions ENABLE ROW LEVEL SECURITY;

--
-- Name: sso_domains; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.sso_domains ENABLE ROW LEVEL SECURITY;

--
-- Name: sso_providers; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.sso_providers ENABLE ROW LEVEL SECURITY;

--
-- Name: users; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.users ENABLE ROW LEVEL SECURITY;

--
-- Name: availability_calendar Admins can manage availability; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can manage availability" ON public.availability_calendar USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));


--
-- Name: booking_requests Admins can manage booking requests; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can manage booking requests" ON public.booking_requests USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));


--
-- Name: bookings Admins can manage bookings; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can manage bookings" ON public.bookings USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));


--
-- Name: damage_claims Admins can manage damage claims; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can manage damage claims" ON public.damage_claims USING (public.is_admin(auth.uid()));


--
-- Name: equipment Admins can manage equipment; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can manage equipment" ON public.equipment USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));


--
-- Name: equipment_inspections Admins can manage equipment inspections; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can manage equipment inspections" ON public.equipment_inspections USING (public.is_admin(auth.uid()));


--
-- Name: equipment_photos Admins can manage equipment photos; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can manage equipment photos" ON public.equipment_photos USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));


--
-- Name: owner_profiles Admins can manage owner profiles; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can manage owner profiles" ON public.owner_profiles USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));


--
-- Name: payments Admins can manage payments; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can manage payments" ON public.payments USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));


--
-- Name: profiles Admins can manage profiles; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can manage profiles" ON public.profiles USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));


--
-- Name: renter_profiles Admins can manage renter profiles; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can manage renter profiles" ON public.renter_profiles USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));


--
-- Name: user_verifications Admins can manage user verifications; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can manage user verifications" ON public.user_verifications USING (public.is_admin(auth.uid()));


--
-- Name: equipment Anon users can view available equipment; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Anon users can view available equipment" ON public.equipment FOR SELECT TO anon USING ((is_available = true));


--
-- Name: content_translations Anyone can read translations; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Anyone can read translations" ON public.content_translations FOR SELECT TO authenticated, anon USING (true);


--
-- Name: availability_calendar Anyone can view availability calendar; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Anyone can view availability calendar" ON public.availability_calendar FOR SELECT USING (true);


--
-- Name: categories Anyone can view categories; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Anyone can view categories" ON public.categories FOR SELECT USING (true);


--
-- Name: equipment_photos Anyone can view equipment photos; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Anyone can view equipment photos" ON public.equipment_photos FOR SELECT USING (true);


--
-- Name: reviews Anyone can view reviews; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Anyone can view reviews" ON public.reviews FOR SELECT USING (true);


--
-- Name: content_translations Authenticated owners can delete translations; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Authenticated owners can delete translations" ON public.content_translations FOR DELETE TO authenticated USING ((EXISTS ( SELECT 1
   FROM public.equipment e
  WHERE ((e.id = content_translations.content_id) AND (e.owner_id = auth.uid()) AND ((content_translations.content_type)::text = 'equipment'::text)))));


--
-- Name: booking_requests Authenticated users can update booking requests; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Authenticated users can update booking requests" ON public.booking_requests FOR UPDATE TO authenticated USING (((auth.uid() IS NOT NULL) AND ((auth.uid() = renter_id) OR (EXISTS ( SELECT 1
   FROM public.equipment
  WHERE ((equipment.id = booking_requests.equipment_id) AND (equipment.owner_id = auth.uid())))))));


--
-- Name: bookings Authenticated users can update bookings; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Authenticated users can update bookings" ON public.bookings FOR UPDATE TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND ((EXISTS ( SELECT 1
   FROM public.booking_requests
  WHERE ((booking_requests.id = bookings.booking_request_id) AND (booking_requests.renter_id = ( SELECT auth.uid() AS uid))))) OR (EXISTS ( SELECT 1
   FROM (public.booking_requests
     JOIN public.equipment ON ((equipment.id = booking_requests.equipment_id)))
  WHERE ((booking_requests.id = bookings.booking_request_id) AND (equipment.owner_id = ( SELECT auth.uid() AS uid))))))));


--
-- Name: profiles Authenticated users can update profiles; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Authenticated users can update profiles" ON public.profiles FOR UPDATE TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (( SELECT auth.uid() AS uid) = id))) WITH CHECK (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (( SELECT auth.uid() AS uid) = id)));


--
-- Name: POLICY "Authenticated users can update profiles" ON profiles; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON POLICY "Authenticated users can update profiles" ON public.profiles IS 'Allows users to update their own profile. Role changes are prevented by the prevent_role_escalation_trigger. Role changes to admin can only be made by administrators through the admin dashboard.';


--
-- Name: booking_requests Authenticated users can view booking requests; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Authenticated users can view booking requests" ON public.booking_requests FOR SELECT TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND ((( SELECT auth.uid() AS uid) = renter_id) OR (EXISTS ( SELECT 1
   FROM public.equipment
  WHERE ((equipment.id = booking_requests.equipment_id) AND (equipment.owner_id = ( SELECT auth.uid() AS uid))))) OR (EXISTS ( SELECT 1
   FROM public.equipment
  WHERE ((equipment.id = booking_requests.equipment_id) AND (equipment.is_available = true)))))));


--
-- Name: bookings Authenticated users can view bookings; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Authenticated users can view bookings" ON public.bookings FOR SELECT TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND ((EXISTS ( SELECT 1
   FROM public.booking_requests
  WHERE ((booking_requests.id = bookings.booking_request_id) AND (booking_requests.renter_id = ( SELECT auth.uid() AS uid))))) OR (EXISTS ( SELECT 1
   FROM (public.booking_requests
     JOIN public.equipment ON ((equipment.id = booking_requests.equipment_id)))
  WHERE ((booking_requests.id = bookings.booking_request_id) AND (equipment.owner_id = ( SELECT auth.uid() AS uid))))))));


--
-- Name: equipment Authenticated users can view equipment; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Authenticated users can view equipment" ON public.equipment FOR SELECT TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND ((is_available = true) OR (( SELECT auth.uid() AS uid) = owner_id))));


--
-- Name: payments Authenticated users can view payments; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Authenticated users can view payments" ON public.payments FOR SELECT TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND ((renter_id = ( SELECT auth.uid() AS uid)) OR (owner_id = ( SELECT auth.uid() AS uid)) OR (EXISTS ( SELECT 1
   FROM public.booking_requests
  WHERE ((booking_requests.id = payments.booking_request_id) AND (booking_requests.renter_id = ( SELECT auth.uid() AS uid))))) OR (EXISTS ( SELECT 1
   FROM (public.booking_requests
     JOIN public.equipment ON ((equipment.id = booking_requests.equipment_id)))
  WHERE ((booking_requests.id = payments.booking_request_id) AND (equipment.owner_id = ( SELECT auth.uid() AS uid))))))));


--
-- Name: profiles Authenticated users can view profiles; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Authenticated users can view profiles" ON public.profiles FOR SELECT TO authenticated USING ((( SELECT auth.uid() AS uid) IS NOT NULL));


--
-- Name: availability_calendar Equipment owners can delete availability; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Equipment owners can delete availability" ON public.availability_calendar FOR DELETE TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (EXISTS ( SELECT 1
   FROM public.equipment
  WHERE ((equipment.id = availability_calendar.equipment_id) AND (equipment.owner_id = ( SELECT auth.uid() AS uid)))))));


--
-- Name: equipment_photos Equipment owners can delete photos; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Equipment owners can delete photos" ON public.equipment_photos FOR DELETE TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (EXISTS ( SELECT 1
   FROM public.equipment
  WHERE ((equipment.id = equipment_photos.equipment_id) AND (equipment.owner_id = ( SELECT auth.uid() AS uid)))))));


--
-- Name: availability_calendar Equipment owners can insert availability; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Equipment owners can insert availability" ON public.availability_calendar FOR INSERT TO authenticated WITH CHECK (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (EXISTS ( SELECT 1
   FROM public.equipment
  WHERE ((equipment.id = availability_calendar.equipment_id) AND (equipment.owner_id = ( SELECT auth.uid() AS uid)))))));


--
-- Name: equipment_photos Equipment owners can insert photos; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Equipment owners can insert photos" ON public.equipment_photos FOR INSERT TO authenticated WITH CHECK (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (EXISTS ( SELECT 1
   FROM public.equipment
  WHERE ((equipment.id = equipment_photos.equipment_id) AND (equipment.owner_id = ( SELECT auth.uid() AS uid)))))));


--
-- Name: availability_calendar Equipment owners can update availability; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Equipment owners can update availability" ON public.availability_calendar FOR UPDATE TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (EXISTS ( SELECT 1
   FROM public.equipment
  WHERE ((equipment.id = availability_calendar.equipment_id) AND (equipment.owner_id = ( SELECT auth.uid() AS uid)))))));


--
-- Name: equipment_photos Equipment owners can update photos; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Equipment owners can update photos" ON public.equipment_photos FOR UPDATE TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (EXISTS ( SELECT 1
   FROM public.equipment
  WHERE ((equipment.id = equipment_photos.equipment_id) AND (equipment.owner_id = ( SELECT auth.uid() AS uid)))))));


--
-- Name: equipment Owners can delete their own equipment; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Owners can delete their own equipment" ON public.equipment FOR DELETE TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (( SELECT auth.uid() AS uid) = owner_id)));


--
-- Name: damage_claims Owners can file claims for their equipment; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Owners can file claims for their equipment" ON public.damage_claims FOR INSERT TO authenticated WITH CHECK (((auth.uid() = filed_by) AND (EXISTS ( SELECT 1
   FROM (public.booking_requests br
     JOIN public.equipment e ON ((e.id = br.equipment_id)))
  WHERE ((br.id = damage_claims.booking_id) AND (e.owner_id = auth.uid()))))));


--
-- Name: equipment Owners can insert their own equipment; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Owners can insert their own equipment" ON public.equipment FOR INSERT TO authenticated WITH CHECK (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (( SELECT auth.uid() AS uid) = owner_id)));


--
-- Name: equipment Owners can update their own equipment; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Owners can update their own equipment" ON public.equipment FOR UPDATE TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (( SELECT auth.uid() AS uid) = owner_id)));


--
-- Name: damage_claims Related users can update claims; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Related users can update claims" ON public.damage_claims FOR UPDATE TO authenticated USING (((auth.uid() = filed_by) OR (EXISTS ( SELECT 1
   FROM public.booking_requests br
  WHERE ((br.id = damage_claims.booking_id) AND (br.renter_id = auth.uid()))))));


--
-- Name: booking_requests Renters can create booking requests; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Renters can create booking requests" ON public.booking_requests FOR INSERT TO authenticated WITH CHECK (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (( SELECT auth.uid() AS uid) = renter_id)));


--
-- Name: booking_requests Renters can delete their own pending booking requests; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Renters can delete their own pending booking requests" ON public.booking_requests FOR DELETE TO authenticated USING (((( SELECT auth.uid() AS uid) = renter_id) AND (status = 'pending'::public.booking_status)));


--
-- Name: content_translations Service role can delete any translations; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Service role can delete any translations" ON public.content_translations FOR DELETE TO service_role USING (true);


--
-- Name: content_translations Service role can insert any translations; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Service role can insert any translations" ON public.content_translations FOR INSERT TO service_role WITH CHECK (true);


--
-- Name: content_translations Service role can select any translations; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Service role can select any translations" ON public.content_translations FOR SELECT TO service_role USING (true);


--
-- Name: content_translations Service role can update any translations; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Service role can update any translations" ON public.content_translations FOR UPDATE TO service_role USING (true);


--
-- Name: user_favorites Users can add favorites; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can add favorites" ON public.user_favorites FOR INSERT WITH CHECK ((auth.uid() = user_id));


--
-- Name: conversation_participants Users can add participants to conversations they are in; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can add participants to conversations they are in" ON public.conversation_participants FOR INSERT TO authenticated WITH CHECK (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (EXISTS ( SELECT 1
   FROM public.conversations
  WHERE ((conversations.id = conversation_participants.conversation_id) AND (( SELECT auth.uid() AS uid) = ANY (conversations.participants)))))));


--
-- Name: conversations Users can create conversations; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can create conversations" ON public.conversations FOR INSERT TO authenticated WITH CHECK (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (( SELECT auth.uid() AS uid) = ANY (participants))));


--
-- Name: equipment_inspections Users can create inspections for their bookings; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can create inspections for their bookings" ON public.equipment_inspections FOR INSERT TO authenticated WITH CHECK (((EXISTS ( SELECT 1
   FROM public.booking_requests br
  WHERE ((br.id = equipment_inspections.booking_id) AND (br.renter_id = auth.uid())))) OR (EXISTS ( SELECT 1
   FROM (public.booking_requests br
     JOIN public.equipment e ON ((e.id = br.equipment_id)))
  WHERE ((br.id = equipment_inspections.booking_id) AND (e.owner_id = auth.uid()))))));


--
-- Name: rental_events Users can create rental events for their bookings; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can create rental events for their bookings" ON public.rental_events FOR INSERT WITH CHECK ((EXISTS ( SELECT 1
   FROM (public.booking_requests br
     JOIN public.equipment e ON ((br.equipment_id = e.id)))
  WHERE ((br.id = rental_events.booking_id) AND ((br.renter_id = auth.uid()) OR (e.owner_id = auth.uid()))))));


--
-- Name: reviews Users can create reviews for their bookings; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can create reviews for their bookings" ON public.reviews FOR INSERT WITH CHECK ((EXISTS ( SELECT 1
   FROM (public.booking_requests br
     JOIN public.equipment e ON ((e.id = br.equipment_id)))
  WHERE ((br.id = reviews.booking_id) AND ((br.renter_id = auth.uid()) OR (e.owner_id = auth.uid()))))));


--
-- Name: user_verifications Users can create their own verifications; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can create their own verifications" ON public.user_verifications FOR INSERT TO authenticated WITH CHECK (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (( SELECT auth.uid() AS uid) = user_id)));


--
-- Name: conversations Users can delete conversations they participate in; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can delete conversations they participate in" ON public.conversations FOR DELETE TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (( SELECT auth.uid() AS uid) = ANY (participants))));


--
-- Name: messages Users can delete messages they sent; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can delete messages they sent" ON public.messages FOR DELETE TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (( SELECT auth.uid() AS uid) = sender_id)));


--
-- Name: notifications Users can delete own notifications; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can delete own notifications" ON public.notifications FOR DELETE USING ((auth.uid() = user_id));


--
-- Name: content_translations Users can delete translations for own equipment; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can delete translations for own equipment" ON public.content_translations FOR DELETE TO authenticated USING ((((content_type)::text = 'equipment'::text) AND (EXISTS ( SELECT 1
   FROM public.equipment
  WHERE ((equipment.id = content_translations.content_id) AND (equipment.owner_id = auth.uid()))))));


--
-- Name: notification_preferences Users can insert own notification preferences; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can insert own notification preferences" ON public.notification_preferences FOR INSERT WITH CHECK ((auth.uid() = user_id));


--
-- Name: owner_profiles Users can insert their own owner profile; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can insert their own owner profile" ON public.owner_profiles FOR INSERT TO authenticated WITH CHECK (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (( SELECT auth.uid() AS uid) = profile_id)));


--
-- Name: profiles Users can insert their own profile; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can insert their own profile" ON public.profiles FOR INSERT TO authenticated WITH CHECK (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (( SELECT auth.uid() AS uid) = id)));


--
-- Name: renter_profiles Users can insert their own renter profile; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can insert their own renter profile" ON public.renter_profiles FOR INSERT TO authenticated WITH CHECK (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (( SELECT auth.uid() AS uid) = profile_id)));


--
-- Name: content_translations Users can insert translations for own equipment; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can insert translations for own equipment" ON public.content_translations FOR INSERT TO authenticated WITH CHECK ((((content_type)::text = 'equipment'::text) AND (EXISTS ( SELECT 1
   FROM public.equipment
  WHERE ((equipment.id = content_translations.content_id) AND (equipment.owner_id = auth.uid()))))));


--
-- Name: user_favorites Users can remove favorites; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can remove favorites" ON public.user_favorites FOR DELETE USING ((auth.uid() = user_id));


--
-- Name: conversation_participants Users can remove themselves from conversations; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can remove themselves from conversations" ON public.conversation_participants FOR DELETE TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (( SELECT auth.uid() AS uid) = profile_id)));


--
-- Name: content_translations Users can select translations for own equipment; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can select translations for own equipment" ON public.content_translations FOR SELECT TO authenticated USING ((((content_type)::text = 'equipment'::text) AND (EXISTS ( SELECT 1
   FROM public.equipment
  WHERE ((equipment.id = content_translations.content_id) AND (equipment.owner_id = auth.uid()))))));


--
-- Name: messages Users can send messages to their conversations; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can send messages to their conversations" ON public.messages FOR INSERT TO authenticated WITH CHECK (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (( SELECT auth.uid() AS uid) = sender_id) AND (EXISTS ( SELECT 1
   FROM public.conversations
  WHERE ((conversations.id = messages.conversation_id) AND (( SELECT auth.uid() AS uid) = ANY (conversations.participants)))))));


--
-- Name: conversations Users can update conversations they participate in; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can update conversations they participate in" ON public.conversations FOR UPDATE TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (( SELECT auth.uid() AS uid) = ANY (participants))));


--
-- Name: messages Users can update messages they sent; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can update messages they sent" ON public.messages FOR UPDATE TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (( SELECT auth.uid() AS uid) = sender_id)));


--
-- Name: notification_preferences Users can update own notification preferences; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can update own notification preferences" ON public.notification_preferences FOR UPDATE USING ((auth.uid() = user_id)) WITH CHECK ((auth.uid() = user_id));


--
-- Name: notifications Users can update own notifications; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can update own notifications" ON public.notifications FOR UPDATE USING ((auth.uid() = user_id)) WITH CHECK ((auth.uid() = user_id));


--
-- Name: owner_profiles Users can update their own owner profile; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can update their own owner profile" ON public.owner_profiles FOR UPDATE TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (( SELECT auth.uid() AS uid) = profile_id)));


--
-- Name: renter_profiles Users can update their own renter profile; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can update their own renter profile" ON public.renter_profiles FOR UPDATE TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (( SELECT auth.uid() AS uid) = profile_id)));


--
-- Name: reviews Users can update their own reviews; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can update their own reviews" ON public.reviews FOR UPDATE TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (( SELECT auth.uid() AS uid) = reviewer_id)));


--
-- Name: user_verifications Users can update their own verifications; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can update their own verifications" ON public.user_verifications FOR UPDATE TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (( SELECT auth.uid() AS uid) = user_id)));


--
-- Name: equipment_inspections Users can update their verification on inspections; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can update their verification on inspections" ON public.equipment_inspections FOR UPDATE TO authenticated USING ((((EXISTS ( SELECT 1
   FROM public.booking_requests br
  WHERE ((br.id = equipment_inspections.booking_id) AND (br.renter_id = auth.uid())))) AND (NOT verified_by_renter)) OR ((EXISTS ( SELECT 1
   FROM (public.booking_requests br
     JOIN public.equipment e ON ((e.id = br.equipment_id)))
  WHERE ((br.id = equipment_inspections.booking_id) AND (e.owner_id = auth.uid())))) AND (NOT verified_by_owner)))) WITH CHECK (((EXISTS ( SELECT 1
   FROM public.booking_requests br
  WHERE ((br.id = equipment_inspections.booking_id) AND (br.renter_id = auth.uid())))) OR (EXISTS ( SELECT 1
   FROM (public.booking_requests br
     JOIN public.equipment e ON ((e.id = br.equipment_id)))
  WHERE ((br.id = equipment_inspections.booking_id) AND (e.owner_id = auth.uid()))))));


--
-- Name: content_translations Users can update translations for own equipment; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can update translations for own equipment" ON public.content_translations FOR UPDATE TO authenticated USING ((((content_type)::text = 'equipment'::text) AND (EXISTS ( SELECT 1
   FROM public.equipment
  WHERE ((equipment.id = content_translations.content_id) AND (equipment.owner_id = auth.uid()))))));


--
-- Name: damage_claims Users can view claims related to their bookings; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can view claims related to their bookings" ON public.damage_claims FOR SELECT TO authenticated USING (((auth.uid() = filed_by) OR (EXISTS ( SELECT 1
   FROM public.booking_requests br
  WHERE ((br.id = damage_claims.booking_id) AND (br.renter_id = auth.uid()))))));


--
-- Name: conversations Users can view conversations they participate in; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can view conversations they participate in" ON public.conversations FOR SELECT TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (( SELECT auth.uid() AS uid) = ANY (participants))));


--
-- Name: equipment_inspections Users can view inspections for their bookings; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can view inspections for their bookings" ON public.equipment_inspections FOR SELECT TO authenticated USING (((EXISTS ( SELECT 1
   FROM public.booking_requests br
  WHERE ((br.id = equipment_inspections.booking_id) AND (br.renter_id = auth.uid())))) OR (EXISTS ( SELECT 1
   FROM (public.booking_requests br
     JOIN public.equipment e ON ((e.id = br.equipment_id)))
  WHERE ((br.id = equipment_inspections.booking_id) AND (e.owner_id = auth.uid()))))));


--
-- Name: messages Users can view messages in their conversations; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can view messages in their conversations" ON public.messages FOR SELECT TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (EXISTS ( SELECT 1
   FROM public.conversations
  WHERE ((conversations.id = messages.conversation_id) AND (( SELECT auth.uid() AS uid) = ANY (conversations.participants)))))));


--
-- Name: user_favorites Users can view own favorites; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can view own favorites" ON public.user_favorites FOR SELECT USING ((auth.uid() = user_id));


--
-- Name: notification_preferences Users can view own notification preferences; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can view own notification preferences" ON public.notification_preferences FOR SELECT USING ((auth.uid() = user_id));


--
-- Name: notifications Users can view own notifications; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can view own notifications" ON public.notifications FOR SELECT USING ((auth.uid() = user_id));


--
-- Name: conversation_participants Users can view participants of their conversations; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can view participants of their conversations" ON public.conversation_participants FOR SELECT TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (EXISTS ( SELECT 1
   FROM public.conversations
  WHERE ((conversations.id = conversation_participants.conversation_id) AND (( SELECT auth.uid() AS uid) = ANY (conversations.participants)))))));


--
-- Name: rental_events Users can view rental events for their bookings; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can view rental events for their bookings" ON public.rental_events FOR SELECT USING ((EXISTS ( SELECT 1
   FROM (public.booking_requests br
     JOIN public.equipment e ON ((br.equipment_id = e.id)))
  WHERE ((br.id = rental_events.booking_id) AND ((br.renter_id = auth.uid()) OR (e.owner_id = auth.uid()))))));


--
-- Name: booking_history Users can view their own booking history; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can view their own booking history" ON public.booking_history FOR SELECT TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND ((EXISTS ( SELECT 1
   FROM public.booking_requests
  WHERE ((booking_requests.id = booking_history.booking_request_id) AND (booking_requests.renter_id = ( SELECT auth.uid() AS uid))))) OR (EXISTS ( SELECT 1
   FROM (public.booking_requests br
     JOIN public.equipment e ON ((br.equipment_id = e.id)))
  WHERE ((br.id = booking_history.booking_request_id) AND (e.owner_id = ( SELECT auth.uid() AS uid))))))));


--
-- Name: owner_profiles Users can view their own owner profile; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can view their own owner profile" ON public.owner_profiles FOR SELECT TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (( SELECT auth.uid() AS uid) = profile_id)));


--
-- Name: renter_profiles Users can view their own renter profile; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can view their own renter profile" ON public.renter_profiles FOR SELECT TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (( SELECT auth.uid() AS uid) = profile_id)));


--
-- Name: user_verifications Users can view their own verifications; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can view their own verifications" ON public.user_verifications FOR SELECT TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (( SELECT auth.uid() AS uid) = user_id)));


--
-- Name: availability_calendar; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.availability_calendar ENABLE ROW LEVEL SECURITY;

--
-- Name: booking_history; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.booking_history ENABLE ROW LEVEL SECURITY;

--
-- Name: booking_requests; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.booking_requests ENABLE ROW LEVEL SECURITY;

--
-- Name: bookings; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.bookings ENABLE ROW LEVEL SECURITY;

--
-- Name: categories; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.categories ENABLE ROW LEVEL SECURITY;

--
-- Name: content_translations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.content_translations ENABLE ROW LEVEL SECURITY;

--
-- Name: conversation_participants; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.conversation_participants ENABLE ROW LEVEL SECURITY;

--
-- Name: conversations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.conversations ENABLE ROW LEVEL SECURITY;

--
-- Name: damage_claims; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.damage_claims ENABLE ROW LEVEL SECURITY;

--
-- Name: equipment; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.equipment ENABLE ROW LEVEL SECURITY;

--
-- Name: equipment_inspections; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.equipment_inspections ENABLE ROW LEVEL SECURITY;

--
-- Name: equipment_photos; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.equipment_photos ENABLE ROW LEVEL SECURITY;

--
-- Name: messages; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.messages ENABLE ROW LEVEL SECURITY;

--
-- Name: notification_preferences; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.notification_preferences ENABLE ROW LEVEL SECURITY;

--
-- Name: notifications; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;

--
-- Name: owner_profiles; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.owner_profiles ENABLE ROW LEVEL SECURITY;

--
-- Name: payments; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.payments ENABLE ROW LEVEL SECURITY;

--
-- Name: profiles; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

--
-- Name: rental_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.rental_events ENABLE ROW LEVEL SECURITY;

--
-- Name: renter_profiles; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.renter_profiles ENABLE ROW LEVEL SECURITY;

--
-- Name: reviews; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.reviews ENABLE ROW LEVEL SECURITY;

--
-- Name: user_favorites; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.user_favorites ENABLE ROW LEVEL SECURITY;

--
-- Name: user_verifications; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.user_verifications ENABLE ROW LEVEL SECURITY;

--
-- Name: conversation_participants users can update own last_read_at; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "users can update own last_read_at" ON public.conversation_participants FOR UPDATE TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (( SELECT auth.uid() AS uid) = profile_id))) WITH CHECK (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (( SELECT auth.uid() AS uid) = profile_id)));


--
-- Name: messages allow messaging topics; Type: POLICY; Schema: realtime; Owner: -
--

CREATE POLICY "allow messaging topics" ON realtime.messages FOR SELECT TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (((split_part(topic, ':'::text, 1) = 'room'::text) AND (split_part(topic, ':'::text, 2) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'::text) AND (EXISTS ( SELECT 1
   FROM public.conversation_participants cp
  WHERE ((cp.conversation_id = (split_part(messages.topic, ':'::text, 2))::uuid) AND (cp.profile_id = ( SELECT auth.uid() AS uid)))))) OR ((split_part(topic, ':'::text, 1) = 'user'::text) AND (split_part(topic, ':'::text, 2) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'::text) AND ((split_part(topic, ':'::text, 2))::uuid = ( SELECT auth.uid() AS uid))))));


--
-- Name: messages authenticated can receive presence; Type: POLICY; Schema: realtime; Owner: -
--

CREATE POLICY "authenticated can receive presence" ON realtime.messages FOR SELECT TO authenticated USING (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (extension = 'presence'::text) AND ((split_part(topic, ':'::text, 1) = 'presence'::text) OR ((split_part(topic, ':'::text, 1) = 'room'::text) AND (split_part(topic, ':'::text, 2) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'::text) AND (EXISTS ( SELECT 1
   FROM public.conversation_participants cp
  WHERE ((cp.conversation_id = (split_part(messages.topic, ':'::text, 2))::uuid) AND (cp.profile_id = ( SELECT auth.uid() AS uid)))))))));


--
-- Name: messages authenticated can send typing events; Type: POLICY; Schema: realtime; Owner: -
--

CREATE POLICY "authenticated can send typing events" ON realtime.messages FOR INSERT TO authenticated WITH CHECK (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (split_part(topic, ':'::text, 1) = 'room'::text) AND (split_part(topic, ':'::text, 2) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'::text) AND (EXISTS ( SELECT 1
   FROM public.conversation_participants cp
  WHERE ((cp.conversation_id = (split_part(messages.topic, ':'::text, 2))::uuid) AND (cp.profile_id = ( SELECT auth.uid() AS uid)))))));


--
-- Name: messages authenticated can track presence; Type: POLICY; Schema: realtime; Owner: -
--

CREATE POLICY "authenticated can track presence" ON realtime.messages FOR INSERT TO authenticated WITH CHECK (((( SELECT auth.uid() AS uid) IS NOT NULL) AND (extension = 'presence'::text) AND ((split_part(topic, ':'::text, 1) = 'presence'::text) OR ((split_part(topic, ':'::text, 1) = 'room'::text) AND (split_part(topic, ':'::text, 2) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'::text) AND (EXISTS ( SELECT 1
   FROM public.conversation_participants cp
  WHERE ((cp.conversation_id = (split_part(messages.topic, ':'::text, 2))::uuid) AND (cp.profile_id = ( SELECT auth.uid() AS uid)))))))));


--
-- Name: messages; Type: ROW SECURITY; Schema: realtime; Owner: -
--

ALTER TABLE realtime.messages ENABLE ROW LEVEL SECURITY;

--
-- Name: objects Authenticated users can upload equipment photos; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Authenticated users can upload equipment photos" ON storage.objects FOR INSERT TO authenticated WITH CHECK ((bucket_id = 'equipment-photos'::text));


--
-- Name: objects Authenticated users can upload inspection photos; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Authenticated users can upload inspection photos" ON storage.objects FOR INSERT TO authenticated WITH CHECK ((bucket_id = 'inspection-photos'::text));


--
-- Name: objects Public read access to equipment photos; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Public read access to equipment photos" ON storage.objects FOR SELECT USING ((bucket_id = 'equipment-photos'::text));


--
-- Name: objects Public read access to inspection photos; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Public read access to inspection photos" ON storage.objects FOR SELECT USING ((bucket_id = 'inspection-photos'::text));


--
-- Name: objects Users can delete their own equipment photos; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Users can delete their own equipment photos" ON storage.objects FOR DELETE TO authenticated USING (((bucket_id = 'equipment-photos'::text) AND ((auth.uid())::text = (storage.foldername(name))[1])));


--
-- Name: objects Users can delete their own inspection photos; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Users can delete their own inspection photos" ON storage.objects FOR DELETE TO authenticated USING (((bucket_id = 'inspection-photos'::text) AND ((auth.uid())::text = (storage.foldername(name))[1])));


--
-- Name: objects Users can read their own verification documents; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Users can read their own verification documents" ON storage.objects FOR SELECT TO authenticated USING (((bucket_id = 'verification-documents'::text) AND ((auth.uid())::text = (storage.foldername(name))[1])));


--
-- Name: objects Users can update their own equipment photos; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Users can update their own equipment photos" ON storage.objects FOR UPDATE TO authenticated USING (((bucket_id = 'equipment-photos'::text) AND ((auth.uid())::text = (storage.foldername(name))[1])));


--
-- Name: objects Users can upload their own verification documents; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Users can upload their own verification documents" ON storage.objects FOR INSERT TO authenticated WITH CHECK (((bucket_id = 'verification-documents'::text) AND ((auth.uid())::text = (storage.foldername(name))[1])));


--
-- Name: buckets; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE storage.buckets ENABLE ROW LEVEL SECURITY;

--
-- Name: buckets_analytics; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE storage.buckets_analytics ENABLE ROW LEVEL SECURITY;

--
-- Name: buckets_vectors; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE storage.buckets_vectors ENABLE ROW LEVEL SECURITY;

--
-- Name: migrations; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE storage.migrations ENABLE ROW LEVEL SECURITY;

--
-- Name: objects; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;

--
-- Name: s3_multipart_uploads; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE storage.s3_multipart_uploads ENABLE ROW LEVEL SECURITY;

--
-- Name: s3_multipart_uploads_parts; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE storage.s3_multipart_uploads_parts ENABLE ROW LEVEL SECURITY;

--
-- Name: vector_indexes; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE storage.vector_indexes ENABLE ROW LEVEL SECURITY;

--
-- Name: supabase_realtime; Type: PUBLICATION; Schema: -; Owner: -
--

CREATE PUBLICATION supabase_realtime WITH (publish = 'insert, update, delete, truncate');


--
-- Name: supabase_realtime_messages_publication; Type: PUBLICATION; Schema: -; Owner: -
--

CREATE PUBLICATION supabase_realtime_messages_publication WITH (publish = 'insert, update, delete, truncate');


--
-- Name: supabase_realtime notifications; Type: PUBLICATION TABLE; Schema: public; Owner: -
--

ALTER PUBLICATION supabase_realtime ADD TABLE ONLY public.notifications;


--
-- Name: supabase_realtime_messages_publication messages; Type: PUBLICATION TABLE; Schema: realtime; Owner: -
--

ALTER PUBLICATION supabase_realtime_messages_publication ADD TABLE ONLY realtime.messages;


--
-- Name: issue_graphql_placeholder; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER issue_graphql_placeholder ON sql_drop
         WHEN TAG IN ('DROP EXTENSION')
   EXECUTE FUNCTION extensions.set_graphql_placeholder();


--
-- Name: issue_pg_cron_access; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER issue_pg_cron_access ON ddl_command_end
         WHEN TAG IN ('CREATE EXTENSION')
   EXECUTE FUNCTION extensions.grant_pg_cron_access();


--
-- Name: issue_pg_graphql_access; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER issue_pg_graphql_access ON ddl_command_end
         WHEN TAG IN ('CREATE FUNCTION')
   EXECUTE FUNCTION extensions.grant_pg_graphql_access();


--
-- Name: issue_pg_net_access; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER issue_pg_net_access ON ddl_command_end
         WHEN TAG IN ('CREATE EXTENSION')
   EXECUTE FUNCTION extensions.grant_pg_net_access();


--
-- Name: pgrst_ddl_watch; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER pgrst_ddl_watch ON ddl_command_end
   EXECUTE FUNCTION extensions.pgrst_ddl_watch();


--
-- Name: pgrst_drop_watch; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER pgrst_drop_watch ON sql_drop
   EXECUTE FUNCTION extensions.pgrst_drop_watch();


--
-- PostgreSQL database dump complete
--

\unrestrict RexxHFwxBHHUwpGswBcpsq6whlfPgMjqrRoGFRJaarjXjqAvQ3hfzHGxMnwAfwa

