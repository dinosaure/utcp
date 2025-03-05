let src = Logs.Src.create "fragment"

module Log = (val Logs.src_log src : Logs.LOG)

type header =
  { src : Ipaddr.V4.t
  ; dst : Ipaddr.V4.t
  ; protocol : protocol
  ; uid : int }
and protocol = ICMP | TCP | UDP
and fragmented = |
and unfragmented = |

type 'a payload =
  | Unsized : Ropes.unknown Ropes.t -> fragmented payload
  | Sized : Diet.t * bytes -> fragmented payload
  | Unfragmented : Bstr.t -> unfragmented payload

type t = Payload : 'a payload -> t [@@unboxed]

let singleton ~off ?(limit= false) str : t =
  let empty = Ropes.(Unknown Limitless) in
  let ropes = Ropes.insert ~off str empty in
  match limit with
  | false ->
    Log.debug (fun m -> m "+%d byte(s) %@ %d" (String.length str) off);
    Payload (Unsized ropes)
  | true ->
    let max = off + String.length str in
    Log.debug (fun m -> m "+%d byte(s) %@ %d (max: %d)" (String.length str) off max);
    let ropes = Ropes.fix ~max ropes in
    let diet, buf = Ropes.to_bytes ropes in
    Payload (Sized (diet, buf))

exception Out_of_bounds
exception Overlap

let () = Printexc.register_printer @@ function
  | Out_of_bounds -> Some "Fragment out of bounds"
  | Overlap -> Some "Fragment overlap"
  | _ -> None

let insert (t : fragmented payload) ~off ?(limit= false) str =
  match t, limit with
  | Sized (diet, buf), false ->
      let len = String.length str in
      if off < 0
      || off > Bytes.length buf - len
      then raise_notrace Out_of_bounds;
      begin try
        let diet = Diet.add ~off ~len diet in
        Bytes.unsafe_blit_string str 0 buf off len;
        Sized (diet, buf)
      with _ -> raise_notrace Overlap end
  | Unsized ropes, false ->
      Log.debug (fun m -> m "+%d byte(s) %@ %d" (String.length str) off);
      let ropes = Ropes.insert ~off str ropes in
      (* NOTE(dinosaure): actually, we  can increase the ropes without limit.
         This is also the case with [mirage-tcpip], which has no mechanism to
         limit the [payload]. Not sure if you should put a limit or not. *)
      Unsized ropes
  | Sized _, true -> failwith "Multiple MF:0 fragments"
  | Unsized ropes, true ->
      let max = off + String.length str in
      Log.debug (fun m -> m "+%d byte(s) %@ %d (max: %d)" (String.length str) off max);
      let ropes = Ropes.insert ~off str ropes in
      let ropes = Ropes.fix ~max ropes in
      let diet, buf = Ropes.to_bytes ropes in
      Sized (diet, buf)

let is_complete : type a. a payload -> bool = function
  | Unsized _ -> false
  | Sized (diet, buf) ->
      let buf = Diet.add ~off:0 ~len:(Bytes.length buf) Diet.empty in
      Diet.(is_empty (diff diet buf))
  | Unfragmented _ -> true

let reassemble_exn : fragmented payload -> string = function
  | Unsized _ -> invalid_arg "Fragment.reassemble_exn"
  | Sized (_, buf) -> Bytes.unsafe_to_string buf
