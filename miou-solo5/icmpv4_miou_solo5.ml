module Packet = struct
  type t =
    { code : int
    ; kind : kind
    ; payload : string }
  and kind =
    | Echo_reply
    | Destination_unreachable
    | Source_quench
    | Redirect
    | Echo_request
    | Time_exceeded
    | Parameter_problem
    | Timestamp_request
    | Timestamp_reply
    | Information_request
    | Information_reply

  open Bin

  let kind =
    let f = function
      | 0 -> Echo_reply
      | 3 -> Destination_unreachable
      | 4 -> Source_quench
      | 5 -> Redirect
      | 8 -> Echo_request
      | 11 -> Time_exceeded
      | 12 -> Parameter_problem
      | 13 -> Timestamp_request
      | 14 -> Timestamp_reply
      | 15 -> Information_request
      | 16 -> Information_reply
      | _ -> invalid_arg "Invalid ICMPv4 message" in
    let g = function
      | Echo_reply -> 0
      | Destination_unreachable -> 3
      | Source_quench -> 4
      | Redirect -> 5
      | Echo_request -> 8
      | Time_exceeded -> 11
      | Parameter_problem -> 12
      | Timestamp_request -> 13
      | Timestamp_reply -> 14
      | Information_request -> 15
      | Information_reply -> 16 in
    map uint8 f g
end
