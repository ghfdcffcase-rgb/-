import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.49.1";
import { AccessToken, RoomServiceClient } from "npm:livekit-server-sdk@2.9.6";

const cors = {
  "Access-Control-Allow-Origin": "https://mithaq-platform.vercel.app",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};
const reply = (status: number, body: Record<string, unknown>) =>
  new Response(JSON.stringify(body), { status, headers: cors });

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return reply(405, { error: "method_not_allowed" });

  const authHeader = req.headers.get("Authorization") || "";
  const jwt = authHeader.replace(/^Bearer\s+/i, "");
  if (!jwt) return reply(401, { error: "auth_required" });

  const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  const livekitUrl = Deno.env.get("LIVEKIT_URL");
  const livekitKey = Deno.env.get("LIVEKIT_API_KEY");
  const livekitSecret = Deno.env.get("LIVEKIT_API_SECRET");
  if (!livekitUrl || !livekitKey || !livekitSecret) {
    return reply(503, { error: "livekit_not_configured", message: "يلزم إعداد مفاتيح LiveKit السرية في Supabase قبل تشغيل البث." });
  }

  const authClient = createClient(supabaseUrl, anonKey, { auth: { persistSession: false, autoRefreshToken: false } });
  const { data: authData, error: authError } = await authClient.auth.getUser(jwt);
  if (authError || !authData.user) return reply(401, { error: "invalid_session" });
  const user = authData.user;

  const db = createClient(supabaseUrl, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } });
  const lk = new RoomServiceClient(livekitUrl, livekitKey, livekitSecret);
  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return reply(400, { error: "invalid_json" }); }
  const action = String(body.action || "");
  const roomId = String(body.roomId || "");
  if (!roomId) return reply(400, { error: "room_required" });

  const { data: room, error: roomError } = await db.from("audio_rooms")
    .select("id,host_user_id,title,room_name,status").eq("id", roomId).maybeSingle();
  if (roomError || !room) return reply(404, { error: "room_not_found" });

  const isHost = room.host_user_id === user.id;
  const { data: admin } = await db.from("admin_users").select("role").eq("user_id", user.id).maybeSingle();
  const isManager = admin?.role === "manager";
  const canModerate = isHost || isManager;

  if (action === "token") {
    if (room.status !== "live" && !(isHost && room.status === "paused")) return reply(409, { error: "room_not_live" });
    let canPublish = false;
    if (isHost) {
      const { data: mm } = await db.from("matchmaker_profiles").select("status").eq("user_id", user.id).maybeSingle();
      if (!mm || !["approved", "active", "verified"].includes(String(mm.status).toLowerCase())) {
        return reply(403, { error: "approved_matchmaker_required" });
      }
      canPublish = room.status === "live";
    } else {
      const { data: request } = await db.from("audio_room_requests").select("status")
        .eq("room_id", room.id).eq("requester_id", user.id).maybeSingle();
      canPublish = request?.status === "approved";
    }
    const at = new AccessToken(livekitKey, livekitSecret, { identity: user.id, ttl: "10m" });
    at.addGrant({ roomJoin: true, room: room.room_name, canPublish, canSubscribe: true, canPublishData: false });
    return reply(200, { token: await at.toJwt(), serverUrl: livekitUrl, canPublish, roomName: room.room_name });
  }

  if (!canModerate) return reply(403, { error: "host_or_manager_required" });

  if (action === "approve_request" || action === "reject_request") {
    const requestId = String(body.requestId || "");
    if (!requestId) return reply(400, { error: "request_required" });
    const status = action === "approve_request" ? "approved" : "rejected";
    const { data: request, error } = await db.from("audio_room_requests").update({ status, updated_at: new Date().toISOString() })
      .eq("id", requestId).eq("room_id", room.id).eq("status", "pending")
      .select("requester_id").maybeSingle();
    if (error || !request) return reply(409, { error: "request_not_pending" });
    if (status === "approved") {
      try { await lk.updateParticipant(room.room_name, request.requester_id, { permission: { canPublish: true, canSubscribe: true } }); } catch { /* participant may join after approval */ }
    }
    return reply(200, { ok: true, status });
  }

  const identity = String(body.identity || "");
  if (action === "set_speaker") {
    if (!identity || identity === room.host_user_id) return reply(400, { error: "invalid_participant" });
    const allow = body.allow === true;
    await lk.updateParticipant(room.room_name, identity, { permission: { canPublish: allow, canSubscribe: true } });
    return reply(200, { ok: true, canPublish: allow });
  }
  if (action === "remove_participant") {
    if (!identity || identity === room.host_user_id) return reply(400, { error: "invalid_participant" });
    await lk.removeParticipant(room.room_name, identity);
    return reply(200, { ok: true });
  }
  if (action === "end_room") {
    await lk.deleteRoom(room.room_name);
    const { error } = await db.from("audio_rooms").update({ status: "ended", ended_at: new Date().toISOString() }).eq("id", room.id);
    if (error) return reply(500, { error: "room_status_update_failed" });
    return reply(200, { ok: true });
  }
  if (action === "pause_room" || action === "resume_room") {
    const status = action === "pause_room" ? "paused" : "live";
    const { error } = await db.from("audio_rooms").update({ status }).eq("id", room.id);
    if (error) return reply(500, { error: "room_status_update_failed" });
    const participants = await lk.listParticipants(room.room_name);
    for (const p of participants) {
      let canPublish = false;
      if (status === "live" && p.identity === room.host_user_id) {
        canPublish = true;
      } else if (status === "live") {
        const { data: approvedRequest } = await db.from("audio_room_requests").select("id")
          .eq("room_id", room.id).eq("requester_id", p.identity).eq("status", "approved").maybeSingle();
        canPublish = !!approvedRequest;
      }
      try { await lk.updateParticipant(room.room_name, p.identity, { permission: { canPublish, canSubscribe: true } }); } catch { /* participant may have disconnected */ }
    }
    return reply(200, { ok: true, status });
  }
  return reply(400, { error: "unsupported_action" });
});