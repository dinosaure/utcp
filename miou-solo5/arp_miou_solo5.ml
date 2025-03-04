module Ethernet = Ethernet_miou_solo5

[@@@warning "-37"]

module Packet = struct
  type t =
    { operation : operation
    ; src_mac : Macaddr.t
    ; dst_mac : Macaddr.t
    ; src_ip : Ipaddr.V4.t
    ; dst_ip : Ipaddr.V4.t }
  and operation =
    | Request | Reply

  open Bin

  let ipaddr = map beint32 Ipaddr.V4.of_int32 Ipaddr.V4.to_int32
  let macaddr = map (bytes 6) Macaddr.of_octets_exn Macaddr.to_octets
  let operation =
    let f = function
      | 1 -> Request
      | 2 -> Reply
      | n -> Fmt.failwith "Invalid ARP operation (%02x)" n in
    let g = function
      | Request -> 1
      | Reply -> 2 in
    map beuint16 f g

  let t =
    let fn _hwtype _ptype _hw_addr_len _p_addr_len
      operation src_mac src_ip dst_mac dst_ip =
        { operation; src_mac; dst_mac; src_ip; dst_ip } in
    record fn
    |+ field beuint16 (Fun.const 1)
    |+ field beuint16 (Fun.const 0x0800)
    |+ field uint8 (Fun.const 6)
    |+ field uint8 (Fun.const 4)
    |+ field operation (fun t -> t.operation)
    |+ field macaddr (fun t -> t.src_mac)
    |+ field ipaddr (fun t -> t.src_ip)
    |+ field macaddr (fun t -> t.dst_mac)
    |+ field ipaddr (fun t -> t.dst_ip)
    |> sealr

  let decode ?(off= 0) bstr =
    try Ok (decode_bstr t bstr (ref off))
    with _exn -> Error `Invalid_ARPv4_packet

  let to_string value = to_string t value
end

let mac0 = Macaddr.of_octets_exn (String.make 6 '\000')

type w = Macaddr.t Miou.Computation.t

type entry =
  | Static of Macaddr.t * bool
  | Dynamic of Macaddr.t * int
  | Pending of w * int

type t =
  { cache : (Ipaddr.V4.t, entry) Hashtbl.t
  ; macaddr : Macaddr.t
  ; ipaddr : Ipaddr.V4.t
  ; timeout : int
  ; retries : int
  ; mutable epoch : int
  ; src : Logs.src
  ; eth : Ethernet.t }

let alias t ipaddr =
  let () = match Hashtbl.find t.cache ipaddr with
    | exception Not_found -> ()
    | Pending (c, _) -> ignore (Miou.Computation.try_return c t.macaddr)
    | _ -> () in
  Hashtbl.replace t.cache ipaddr (Static (t.macaddr, true));
  let pkt =
    { Packet.operation= Packet.Request
    ; src_mac= t.macaddr
    ; dst_mac= mac0
    ; src_ip= ipaddr
    ; dst_ip= ipaddr } in
  (pkt, Macaddr.broadcast)

let write t (arp, dst) =
  let pkt = Packet.to_string arp in
  (* NOTE(dinosaure): During construction, we verified that we could write ARP
     packets and that we would not exceed the MTU. *)
  Ethernet.unsafe_write t.eth ~dst ~protocol:Ethernet.ARPv4 pkt

let guard err fn = if fn () then Ok () else Error err

let create ?(timeout= 800) ?(retries= 5) ?src ?ipaddr eth =
  let ( let* ) = Result.bind in
  let macaddr = Ethernet.macaddr eth in
  (* enough for ARP packets *)
  let* () = guard `MTU_too_small @@ fun () -> Ethernet.mtu eth >= 28 in
  let src = match src with
    | None -> Logs.Src.create (Fmt.str "%a" Macaddr.pp macaddr)
    | Some src -> src in
  if timeout <= 0
  then Fmt.invalid_arg "Arp_miou_solo5.create: null or negative timeout";
  if retries < 0
  then Fmt.invalid_arg "Arg_miou_solo5.create: negative retries value";
  let unknown = Option.is_none ipaddr in
  let ipaddr = Option.value ~default:Ipaddr.V4.any ipaddr in
  let cache = Hashtbl.create 0x10 in
  let t = { cache; macaddr; ipaddr; timeout; retries; epoch= 0; src; eth } in
  if unknown == false
  then write t (alias t ipaddr);
  Ok t

let _ips t =
  let fn ip entry acc = match entry with
    | Static (_, true) -> ip :: acc
    | _ -> acc in
  Hashtbl.fold fn t.cache []

let macaddr t = t.macaddr

let request t dst_ip =
  let dst_mac = Macaddr.broadcast in
  { Packet.operation= Request
  ; src_mac= t.macaddr
  ; dst_mac
  ; src_ip= t.ipaddr
  ; dst_ip }, dst_mac

let reply arp macaddr =
  let pkt =
    { Packet.operation= Packet.Reply
    ; src_mac= macaddr
    ; dst_mac= arp.Packet.src_mac
    ; src_ip= arp.Packet.dst_ip
    ; dst_ip= arp.Packet.src_ip } in
  pkt, arp.Packet.src_mac

exception Timeout
exception Clear

let empty_bt = Printexc.get_callstack 0
let timeout = (Timeout, empty_bt)
let timeout c = ignore (Miou.Computation.try_cancel c timeout)
let clear = (Clear, empty_bt)
let clear c = ignore (Miou.Computation.try_cancel c clear)

let tick t =
  let epoch = t.epoch in
  let fn k v (pkts, to_remove, timeouts) = match v with
    | Dynamic (_, tick) when tick == epoch ->
        pkts, (k :: to_remove), timeouts
    | Dynamic (_, tick) when tick == epoch + 1 ->
        request t k :: pkts, to_remove, timeouts
    | Pending (w, retry) when retry == epoch ->
        pkts, k :: to_remove, w :: timeouts
    | Pending _ -> 
        request t k :: pkts, to_remove, timeouts
    | _ -> pkts, to_remove, timeouts in
  let outs, to_remove, timeouts = Hashtbl.fold fn t.cache ([], [], []) in
  List.iter (Hashtbl.remove t.cache) to_remove;
  List.iter (write t) outs;
  List.iter timeout timeouts;
  t.epoch <- t.epoch + 1

let handle_request t arp =
  let dst = arp.Packet.dst_ip in
  let src = arp.Packet.src_ip in
  let src_mac = arp.Packet.src_mac in
  Logs.debug ~src:t.src (fun m -> m "%a:%a: who has %a?"
    Macaddr.pp src_mac Ipaddr.V4.pp src Ipaddr.V4.pp dst);
  match Hashtbl.find t.cache dst with
  | exception Not_found -> ()
  | Static (macaddr, true) ->
      write t (reply arp macaddr)
  | _ -> ()

let handle_reply t src macaddr =
  let entry = Dynamic (macaddr, t.epoch + t.timeout) in
  Logs.debug ~src:t.src (fun m -> m "handle ARPv4 reply packet from %a:%a"
    Macaddr.pp macaddr Ipaddr.V4.pp src);
  match Hashtbl.find t.cache src with
  | exception Not_found -> ()
  | Static (_, adv) ->
      if adv && Macaddr.compare macaddr mac0 == 0
      then Logs.debug ~src:t.src (fun m -> m "ignoring gratuitious ARP from %a using %a"
        Macaddr.pp macaddr Ipaddr.V4.pp src)
  | Dynamic (macaddr', _) ->
      Logs.debug ~src:t.src (fun m -> m "set %a from %a to %a"
        Ipaddr.V4.pp src Macaddr.pp macaddr' Macaddr.pp macaddr);
      Hashtbl.replace t.cache src entry
  | Pending (c, _) ->
      Logs.debug ~src:t.src (fun m -> m "%a is-at %a"
        Ipaddr.V4.pp src Macaddr.pp macaddr);
      ignore (Miou.Computation.try_return c macaddr);
      Hashtbl.replace t.cache src entry

let input t pkt =
  match Packet.decode pkt.Ethernet.payload with
  | Error _ ->
      let str = Bstr.to_string pkt.payload in
      Logs.err ~src:t.src (fun m -> m "Invalid ARPv4 packet:");
      Logs.err ~src:t.src (fun m -> m "@[<hov>%a@]" (Hxd_string.pp Hxd.default) str)
  | Ok arp ->
      if Ipaddr.V4.compare arp.Packet.src_ip arp.Packet.dst_ip == 0
      || arp.Packet.operation == Packet.Reply
      then
        let mac = arp.Packet.src_mac
        and src = arp.Packet.src_ip in
        handle_reply t src mac
      else handle_request t arp

let to_error (exn, _bt) = match exn with
  | Timeout -> `Timeout
  | Clear -> `Clear
  | exn -> `Exn exn

let query t ipaddr =
  match Hashtbl.find t.cache ipaddr with
  | exception Not_found ->
      let w = Miou.Computation.create () in
      let pending = Pending (w, t.epoch + t.retries) in
      Hashtbl.replace t.cache ipaddr pending;
      write t (request t ipaddr);
      Miou.Computation.await w
      |> Result.map_error to_error
  | Pending (w, _) ->
      Miou.Computation.await w
      |> Result.map_error to_error
  | Static (macaddr, _)
  | Dynamic (macaddr, _) -> Ok macaddr

let ips t =
  let fn k v acc = match v with
    | Static (_, true) -> k :: acc
    | _ -> acc in
  Hashtbl.fold fn t.cache []

let add_ip t ipaddr =
  match ips t with
  | [] ->
      Hashtbl.iter (fun _ -> function
        | Pending (w, _) -> clear w
        | _ -> ()) t.cache;
      Hashtbl.clear t.cache;
      write t (alias t ipaddr)
  | _ ->
      write t (alias t ipaddr)

let set_ips t = function
  | [] ->
      Hashtbl.iter (fun _ -> function
        | Pending (w, _) -> clear w
        | _ -> ()) t.cache;
      Hashtbl.clear t.cache
  | ipaddr :: rest ->
      Hashtbl.iter (fun _ -> function
        | Pending (w, _) -> clear w
        | _ -> ()) t.cache;
      Hashtbl.clear t.cache;
      write t (alias t ipaddr);
      List.iter (add_ip t) rest
