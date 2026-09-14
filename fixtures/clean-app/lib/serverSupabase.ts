import { createClient } from "@supabase/supabase-js";

// Privileged client, constructed only on the server, only from the environment.
export function serverSupabase() {
  return createClient(
    process.env.SUPABASE_URL as string,
    process.env.SUPABASE_SERVICE_ROLE_KEY as string,
  );
}
