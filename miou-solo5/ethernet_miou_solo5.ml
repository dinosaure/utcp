let src = Logs.Src.create "ethernet-miou-solo5"

module Log = (val Logs.src_log src : Logs.LOG)

module Packet = struct
  type protocol =
    | ARPv4
    | IPv4
    | IPv6

  let pp_protocol ppf = function
    | ARPv4 -> Fmt.string ppf "ARPv4"
    | IPv4 -> Fmt.string ppf "IPv4"
    | IPv6 -> Fmt.string ppf "IPv6"

  type t =
    { src : Macaddr.t
    ; dst : Macaddr.t
    ; protocol : protocol option }

  open Bin

  let macaddr = map (bytes 6) Macaddr.of_octets_exn Macaddr.to_octets

  let protocol =
    let f = function
      | 0x0806 -> Some ARPv4
      | 0x0800 -> Some IPv4
      | 0x86dd -> Some IPv6
      | _ -> None in
    let g = function
      | Some ARPv4 -> 0x0806
      | Some IPv4 -> 0x0800
      | Some IPv6 -> 0x86dd
      | None -> Fmt.failwith "Impossible to encode an ethernet frame without a type" in
    map beuint16 f g

  let t =
    let fn src dst protocol =
      { src; dst; protocol } in
    record fn
    |+ field macaddr (fun t -> t.src)
    |+ field macaddr (fun t -> t.dst)
    |+ field protocol (fun t -> t.protocol)
    |> sealr

  let decode bstr =
    try
      let off = ref 0 in
      let pkt = decode_bstr t bstr off in
      let payload = Bstr.shift bstr !off in
      Ok (pkt, payload)
    with _exn -> Error `Invalid_ethernet_packet

  let encode_into ?(off= 0) pkt bstr =
    try
      let off = ref off in
      encode_bstr t pkt bstr off
    with exn ->
      Fmt.failwith "Impossible to encode ethernet packet: %s"
        (Printexc.to_string exn)
end

type protocol = Packet.protocol =
  | ARPv4
  | IPv4
  | IPv6

type t =
  { net : Miou_solo5.Net.t
  ; mutable handler : handler
  ; frames : string packet Queue.t
  ; mtu : int
  ; mac : Macaddr.t
  ; mutex : Miou.Mutex.t
  ; condition : Miou.Condition.t
  ; bstr_ic : Bstr.t
  ; bstr_oc : Bstr.t }
and 'a packet =
  { src : Macaddr.t option
  ; dst : Macaddr.t
  ; protocol : Packet.protocol
  ; payload : 'a }
and handler = Bstr.t packet -> unit

type event = In of Bstr.t | Out

let read_or_write t =
  let prm0 = Miou.async @@ fun () ->
    let len = Miou_solo5.Net.read_bigstring t.net t.bstr_ic in
    In (Bstr.sub t.bstr_ic ~off:0 ~len) in
  let prm1 = Miou.async @@ fun () ->
    Miou.Mutex.protect t.mutex @@ fun () ->
    while Queue.is_empty t.frames do
      Miou.Condition.wait t.condition t.mutex
    done; Out in
  Miou.await_first [ prm0; prm1 ] |> Result.get_ok

let write t packet =
  let src = Option.value ~default:t.mac packet.src in
  let pkt = { Packet.src; dst= packet.dst; protocol= Some packet.protocol } in
  try
    Packet.encode_into ~off:0 pkt t.bstr_oc;
    let len = String.length packet.payload in
    Bstr.blit_from_string packet.payload ~src_off:0 t.bstr_oc ~dst_off:16 ~len;
    Log.debug (fun m -> m "write ethernet packet src:%a -> dst:%a"
      Macaddr.pp src Macaddr.pp packet.dst);
    Miou_solo5.Net.write_bigstring t.net t.bstr_oc
  with exn -> Log.err (fun m -> m "Unexpected exception: %s" (Printexc.to_string exn))

let rec daemon t =
  Log.debug (fun m -> m "ethernet daemon tick");
  Queue.iter (write t) t.frames;
  Queue.clear t.frames;
  match read_or_write t with
  | Out -> Miou.yield (); daemon t
  | In payload ->
     let ok ({ Packet.protocol; src; dst }, payload) =
       match protocol with
       | None -> ()
       | Some protocol ->
         let packet = { src= Some src; dst; protocol; payload } in
         if Macaddr.compare dst t.mac == 0
         || Macaddr.is_unicast dst == false
         then t.handler packet
         else begin
           let payload = Bstr.to_string payload in
           Log.debug (fun m -> m "Ignore packet (src:%a -> dst:%a)" Macaddr.pp src Macaddr.pp dst);
           Log.debug (fun m -> m "Protocol: %a" Packet.pp_protocol protocol);
           Log.debug (fun m -> m "@[<hov>%a@]" (Hxd_string.pp Hxd.default) payload)
         end in
     let error _ =
       let str = Bstr.to_string payload in
       Log.err (fun m -> m "Invalid Ethernet packet");
       Log.err (fun m -> m "@[<hov>%a@]" (Hxd_string.pp Hxd.default) str) in
     let () = Result.fold ~ok ~error (Packet.decode payload) in
     daemon t

let unsafe_write t ?(force= true) ?src ~dst ~protocol payload =
  match force with
  | true ->
    Miou.Mutex.protect t.mutex @@ fun () ->
    Queue.push { src; dst; protocol; payload } t.frames;
    Miou.Condition.signal t.condition
  | false ->
    Queue.push { src; dst; protocol; payload } t.frames

let guard err fn = if fn () then Ok () else Error err

let write t ?force ?src ~dst ~protocol payload =
  let ( let* ) = Result.bind in
  let* () = guard `Exceeds_MTU @@ fun () -> String.length payload <= t.mtu in
  unsafe_write t ?force ?src ~dst ~protocol payload;
  Ok ()

type daemon = unit Miou.t

let create ?(mtu= 1500) ?(handler= ignore) mac net =
  let ( let* ) = Result.bind in
  let* () = guard `MTU_too_small @@ fun () -> mtu > 16 in (* enough for Ethernet packets *)
  let bstr_ic = Bstr.create (16 + mtu) in
  let bstr_oc = Bstr.create (16 + mtu) in
  (* NOTE(dinosaure): the first [Bstr.sub] does a [malloc()], then any
     [Bstr.sub] are cheap. We should use [Slice] instead of [Bstr]. TODO! *)
  let bstr_ic = Bstr.sub bstr_ic ~off:0 ~len:(16 + mtu) in
  let bstr_oc = Bstr.sub bstr_oc ~off:0 ~len:(16 + mtu) in
  let t =
    { net
    ; handler
    ; frames= Queue.create ()
    ; mtu
    ; mac
    ; mutex= Miou.Mutex.create ()
    ; condition= Miou.Condition.create ()
    ; bstr_ic
    ; bstr_oc } in
  let daemon = Miou.async @@ fun () -> daemon t in
  Ok (daemon, t)

let _cnt = Atomic.make 0

let mtu { mtu; _ } = mtu
let macaddr { mac; _ } = mac

let set_handler t handler =
  Atomic.incr _cnt;
  t.handler <- handler;
  if Atomic.get _cnt > 1
  then Log.warn (fun m -> m "Ethernet handler modified more than once")

let kill = Miou.cancel
