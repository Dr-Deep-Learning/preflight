import { supabase } from "../lib/supabaseClient";

export function Profile({ id }: { id: string }) {
  async function load() {
    // No ownership check anywhere: any id returns any user's row.
    const { data } = await supabase.from("profiles").select("*").eq("id", id).single();
    return data;
  }
  return <button onClick={load}>Load profile</button>;
}
