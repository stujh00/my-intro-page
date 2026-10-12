BEGIN;
ALTER TABLE public.t08_challenges ADD COLUMN IF NOT EXISTS context jsonb NOT NULL DEFAULT '{}';

-- These functions are callable ONLY by the server service role.
CREATE OR REPLACE FUNCTION public.t08_finish_registration(
 p_account uuid, p_enrollment_hash text, p_session_hash text,
 p_credential text, p_public_key text, p_counter bigint,
 p_name text, p_transports text[], p_device_type text, p_backed_up boolean
) RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path = '' AS $$
DECLARE a public.t08_accounts%ROWTYPE;
BEGIN
 SELECT * INTO a FROM public.t08_accounts WHERE id=p_account FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'ACCOUNT_NOT_FOUND'; END IF;
 IF p_enrollment_hash IS NOT NULL THEN
  IF a.enrolled_at IS NOT NULL OR a.enrollment_token_hash IS DISTINCT FROM p_enrollment_hash
    OR a.enrollment_expires_at IS NULL OR a.enrollment_expires_at <= now() THEN
   RAISE EXCEPTION 'ENROLLMENT_REJECTED';
  END IF;
 ELSE
  IF NOT EXISTS (SELECT 1 FROM public.t08_sessions WHERE token_hash=p_session_hash
    AND account_id=p_account AND revoked_at IS NULL AND expires_at>now()) THEN
   RAISE EXCEPTION 'SESSION_REJECTED';
  END IF;
 END IF;
 INSERT INTO public.t08_passkeys(credential_id,account_id,public_key,counter,name,transports,device_type,backed_up)
 VALUES(p_credential,p_account,p_public_key,p_counter,p_name,p_transports,p_device_type,p_backed_up);
 IF p_enrollment_hash IS NOT NULL THEN
  UPDATE public.t08_accounts SET enrolled_at=now(),enrollment_token_hash=NULL,
    enrollment_expires_at=NULL WHERE id=p_account;
 END IF;
END $$;

CREATE OR REPLACE FUNCTION public.t08_finish_login(
 p_account uuid,p_credential text,p_old_counter bigint,p_new_counter bigint,p_token_hash text
) RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path = '' AS $$
DECLARE k public.t08_passkeys%ROWTYPE;
BEGIN
 PERFORM 1 FROM public.t08_accounts WHERE id=p_account FOR UPDATE;
 SELECT * INTO k FROM public.t08_passkeys WHERE credential_id=p_credential AND account_id=p_account FOR UPDATE;
 IF NOT FOUND OR k.counter<>p_old_counter THEN RAISE EXCEPTION 'CREDENTIAL_CHANGED'; END IF;
 UPDATE public.t08_passkeys SET counter=p_new_counter WHERE credential_id=p_credential;
 INSERT INTO public.t08_sessions(token_hash,account_id,expires_at)
 VALUES(p_token_hash,p_account,now()+interval '1 hour');
END $$;

CREATE OR REPLACE FUNCTION public.t08_delete_passkey(p_account uuid,p_credential text,p_session_hash text)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path = '' AS $$
BEGIN
 PERFORM 1 FROM public.t08_accounts WHERE id=p_account FOR UPDATE;
 IF NOT EXISTS (SELECT 1 FROM public.t08_sessions WHERE token_hash=p_session_hash
   AND account_id=p_account AND revoked_at IS NULL AND expires_at>now()) THEN
  RAISE EXCEPTION 'SESSION_REJECTED';
 END IF;
 IF NOT EXISTS (SELECT 1 FROM public.t08_passkeys WHERE account_id=p_account AND credential_id=p_credential) THEN
  RAISE EXCEPTION 'CREDENTIAL_NOT_FOUND';
 END IF;
 IF (SELECT count(*) FROM public.t08_passkeys WHERE account_id=p_account)<=1 THEN
  RAISE EXCEPTION 'LAST_PASSKEY';
 END IF;
 DELETE FROM public.t08_passkeys WHERE account_id=p_account AND credential_id=p_credential;
 -- Revoke all existing sessions so a session from the removed key cannot survive.
 UPDATE public.t08_sessions SET revoked_at=now() WHERE account_id=p_account AND revoked_at IS NULL;
END $$;

REVOKE ALL ON FUNCTION public.t08_finish_registration(uuid,text,text,text,text,bigint,text,text[],text,boolean) FROM PUBLIC,anon,authenticated;
REVOKE ALL ON FUNCTION public.t08_finish_login(uuid,text,bigint,bigint,text) FROM PUBLIC,anon,authenticated;
REVOKE ALL ON FUNCTION public.t08_delete_passkey(uuid,text,text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.t08_finish_registration(uuid,text,text,text,text,bigint,text,text[],text,boolean) TO service_role;
GRANT EXECUTE ON FUNCTION public.t08_finish_login(uuid,text,bigint,bigint,text) TO service_role;
GRANT EXECUTE ON FUNCTION public.t08_delete_passkey(uuid,text,text) TO service_role;
COMMIT;
