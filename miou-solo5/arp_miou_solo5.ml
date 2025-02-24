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

  let ipaddr = map (bytes 4) Ipaddr.V4.of_octets_exn Ipaddr.V4.to_octets
  let macaddr = map (bytes 6) Macaddr.of_octets_exn Macaddr.to_octets
  let operation =
    let f = function
      | 0 -> Request
      | 1 -> Reply
      | n -> Fmt.failwith "Invalid ARP operation (%02x)" n in
    let g = function
      | Request -> 0
      | Reply -> 1 in
    map uint8 f g

  let t =
    let fn _hwtype _ptype _hw_addr_len _p_addr_len
      operation src_mac dst_mac src_ip dst_ip =
        { operation; src_mac; dst_mac; src_ip; dst_ip } in
    record fn
    |+ field beuint16 (Fun.const 1)
    |+ field beuint16 (Fun.const 0x0800)
    |+ field uint8 (Fun.const 6)
    |+ field uint8 (Fun.const 4)
    |+ field operation (fun t -> t.operation)
    |+ field macaddr (fun t -> t.src_mac)
    |+ field macaddr (fun t -> t.dst_mac)
    |+ field ipaddr (fun t -> t.src_ip)
    |+ field ipaddr (fun t -> t.dst_ip)
    |> sealr

  let unsafe_decode ?(off= 0) bstr =
    decode_bstr t bstr (ref off)
end

type 'a entry =
  | Static of Macaddr.t * bool
  | Dynamic of Macaddr.t * int
  | Pending of 'a * int

type 'a t =
  { cache : 'a entry Ipaddr.V4.Map.t
  ; mac : Macaddr.t
  ; ip : Ipaddr.V4.t
  ; timeout : int
  ; retries : int
  ; epoch : int }

let ips t =
  let fn ip entry acc = match entry with
    | Static (_, true) -> ip :: acc
    | _ -> acc in
  Ipaddr.V4.Map.fold fn t.cache []

let mac t = t.mac

let pending t ip =
  match Ipaddr.V4.Map.find ip t.cache with
  | exception Not_found -> None
  | Pending (a, _) -> Some a
  | _ -> None

let mac0 = Macaddr.of_octets_exn (String.make 6 '\000')

let alias t ip =
  let cache = Ipaddr.V4.Map.add ip (Static (t.mac, true)) t.cache in
  let packet =
    { Packet.operation= Request
    ; src_mac= t.mac
    ; dst_mac= mac0
    ; src_ip= ip
    ; dst_ip= ip } in
  { t with cache },
  (packet, Macaddr.broadcast),
  pending t ip

let request t dst_ip =
  let dst_mac = Macaddr.broadcast in
  { Packet.operation= Request
  ; src_mac= t.mac 
  ; dst_mac
  ; src_ip= t.ip
  ; dst_ip }, dst_mac

let tick t =
  let epoch = t.epoch in
  let entry k v (cache, acc, r) = match v with
    | Dynamic (_, tick) when tick == epoch ->
        Ipaddr.V4.Map.remove k cache, acc, r
    | Dynamic (_, tick) when tick == epoch + 1 ->
        cache, request t k :: acc, r
    | Pending (a, retry) when retry == epoch ->
        Ipaddr.V4.Map.remove k cache, acc, a :: r
    | Pending _ -> cache, request t k :: acc, r
    | _ -> cache, acc, r in
  let cache, outs, r = Ipaddr.V4.Map.fold entry t.cache  (t.cache, [], []) in
  { t with cache; epoch= t.epoch + 1 }, outs, r
