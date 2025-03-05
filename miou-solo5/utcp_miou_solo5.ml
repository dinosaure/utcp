module Ethernet = Ethernet_miou_solo5
module ARPv4 = Arp_miou_solo5
module IPv4 = Ipv4_miou_solo5
module ICMPv4 = Icmpv4_miou_solo5

exception Net_unreach
exception Closed_by_peer
exception Connection_refused

(* NOTE(dinosaure): μTCP is actually well-abstracted about IPv4 and IPv6 but we
   only have IPv4 implementation. We should handle easily the IPv6 at this
   layer I think. *)
module TCPv4 = struct
  let src = Logs.Src.create "tcpv4"
  
  module Log = (val Logs.src_log src : Logs.LOG)

  type w = (unit, [ `Eof | `Msg of string ]) result Miou.Computation.t

  type state =
    { mutable tcp : w Utcp.state
    ; ipv4 : IPv4.t
    ; queue : Utcp.output Queue.t
    ; mutex : Miou.Mutex.t
    ; condition : Miou.Condition.t
    ; orphans : unit Miou.orphans }

  type flow =
    { state : state
    ; src : Logs.src
    ; flow : Utcp.flow }

  let[@inline] now () =
    let n = Miou_solo5.clock_monotonic () in
    Mtime.of_uint64_ns (Int64.of_int n)

  let write_ipv4 ipv4 (src, dst, seg) =
    let len = Utcp.Segment.length seg in
    Log.debug (fun m -> m "write-out %d byte(s) to %a" len Ipaddr.V4.pp dst);
    if len > IPv4.max ipv4
    then invalid_arg "Impossible to write such IPv4 packet, too huge.";
    let fn bstr =
      (* TODO(dinosaure): the IPv4 can actually pass the pseudo-header
         but μTCP calculate it for us. *)
      let cs = Cstruct.of_bigarray bstr in
      let src = Ipaddr.V4 src
      and dst = Ipaddr.V4 dst in
      Utcp.Segment.encode_and_checksum_into (now ()) cs ~src ~dst seg in
    let pkt = IPv4.Writer.into ~len (Seq.return fn) in
    match IPv4.write ipv4 ~src dst IPv4.TCP pkt with
    | Ok () -> ()
    | Error `Route_not_found ->
        Log.err (fun m -> m "%a is unreachable" Ipaddr.V4.pp dst);
        raise Net_unreach

  let write_ip ipv4 (src, dst, seg) =
    match src, dst with
    | Ipaddr.V4 src, Ipaddr.V4 dst -> write_ipv4 ipv4 (src, dst, seg)
    | _ -> failwith "IPv6 not implemented"

  type result =
    | Data of string
    | Eof
    | Refused

  let read t =
    match Utcp.recv t.state.tcp (now ()) t.flow with
    | Ok (tcp, data, c, segs) ->
        t.state.tcp <- tcp;
        List.iter (write_ip t.state.ipv4) segs;
        if Cstruct.length data == 0
        then match Miou.Computation.await_exn c with
        | Ok () ->
            begin match Utcp.recv t.state.tcp (now ()) t.flow with
            | Ok (tcp, data, _c, segs) ->
                (* TODO(dinosaure): assert (c == _c)? *)
                t.state.tcp <- tcp;
                List.iter (write_ip t.state.ipv4) segs;
                Data (Cstruct.to_string data)
            | Error `Eof -> Eof
            | Error (`Msg msg) ->
                Logs.err ~src:t.src (fun m -> m "%a error while read (second recv): %s"
                  Utcp.pp_flow t.flow msg);
                Refused end
        | Error `Eof -> Eof
        | Error (`Msg msg) ->
            Logs.err ~src:t.src (fun m -> m "%a error from computation while recv: %s"
              Utcp.pp_flow t.flow msg);
            Refused
        else Data (Cstruct.to_string data)
    | Error `Eof -> Eof
    | Error (`Msg msg) ->
        Logs.err ~src:t.src (fun m -> m "%a error while read: %s"
          Utcp.pp_flow t.flow msg);
        Refused

  (* NOTE(dinosaure): μTCP takes the ownership on [cs], so we can not use a
     internal buffer associated to our flow to avoid allocation-per-writing. The
     only viable solution seems to modify μTCP to use strings instead of
     [Cstruct.t]... *)
  let rec write t cs =
    match Utcp.send t.state.tcp (now ()) t.flow cs with
    | Error (`Msg msg) ->
        Logs.err ~src:t.src (fun m -> m "%a error while write: %s"
          Utcp.pp_flow t.flow msg);
        raise Closed_by_peer
    | Ok (tcp, bytes_sent, c, segs) ->
        t.state.tcp <- tcp;
        List.iter (write_ip t.state.ipv4) segs;
        if bytes_sent < Cstruct.length cs
        then
          let result = Miou.Computation.await_exn c in
          match result with
          | Error `Eof -> raise Closed_by_peer
          | Error (`Msg msg) ->
              Logs.err ~src:t.src (fun m -> m "%a error from condition while sending: %s"
                Utcp.pp_flow t.flow msg);
              raise Closed_by_peer
          | Ok () -> write t (Cstruct.shift cs bytes_sent)

  let write t str = write t (Cstruct.of_string str)

  let close t =
    match Utcp.close t.state.tcp (now ()) t.flow with
    | Ok (tcp, segs) ->
        t.state.tcp <- tcp;
        List.iter (write_ip t.state.ipv4) segs
    | Error (`Msg msg) ->
        Logs.err ~src:t.src (fun m -> m "%a error in close: %s"
          Utcp.pp_flow t.flow msg)

  let eof = Error `Eof
  let ok = Ok ()
  let eof c = ignore (Miou.Computation.try_return c eof)
  let ok c = ignore (Miou.Computation.try_return c ok)

  let handler state (pkt, payload) =
    let src = Ipaddr.V4 pkt.IPv4.src in
    let dst = Ipaddr.V4 pkt.IPv4.dst in
    (* NOTE(dinosaure): μTCP takes the ownership on [cs] also. We can try to
       think, a bit deeply, about a zero-copy which includes the TCP layer if
       the given packet is not a part of a _segment_ but it requires some work
       on the μTCP side. Also, μTCP works with [mirage-tcpip] because
       [mirage-net-solo5] copies frames — which is not the case here! At least,
       we make the copy as far as possible.

       RE-NOTE(dinosaure): the viewer can say that we also do the copy for
       ARPv4 and ICMPv4 but they are not a part of our "happy-path". What we
       want to improve is the TCP/IP stack. ARPv4 & ICMPv4 are just side
       protocols. *)
    let cs = match payload with
      | IPv4.Bstr bstr -> Cstruct.of_bigarray (Bstr.copy bstr)
      | IPv4.String str -> Cstruct.of_string str in
    let tcp, ev, segs = Utcp.handle_buf state.tcp (now ()) ~src ~dst cs in
    state.tcp <- tcp;
    let none = ()
    and some = function
      | `Established (flow, c) ->
          Log.debug (fun m -> m "connection established (%a)" Utcp.pp_flow flow);
          Option.iter ok c
      | `Drop (flow, c, cs) ->
          Log.debug (fun m -> m "drop (%a)" Utcp.pp_flow flow);
          List.iter eof cs;
          Option.iter ok c
      | `Signal (flow, cs) ->
          Log.debug (fun m -> m "signal (%a)" Utcp.pp_flow flow);
          List.iter ok cs in
    Option.fold ~none ~some ev;
    Miou.Mutex.protect state.mutex @@ fun () ->
    List.iter (fun out -> Queue.push out state.queue) segs;
    Miou.Condition.signal state.condition

  let rec transfer state acc = match Queue.pop state.queue with
    | exception Queue.Empty -> acc
    | out -> transfer state (out :: acc)

  type event =
    | Out of Utcp.output list
    | Tick

  let write_or_sync state =
    let prm1 = Miou.async @@ fun () ->
      Miou.Mutex.protect state.mutex @@ fun () ->
      if Queue.is_empty state.queue
      then Miou.Condition.wait state.condition state.mutex;
      Out (transfer state []) in
    let prm0 = Miou.async @@ fun () ->
      Miou_solo5.sleep 100_000_000; Tick in
    match Miou.await_first [ prm0; prm1 ] with
    | Ok Tick -> []
    | Ok (Out outs) -> outs
    | Error exn ->
        Log.err (fun m -> m "Unexpected exception: %s" (Printexc.to_string exn));
        []

  let rec clean orphans = match Miou.care orphans with
    | None | Some None -> ()
    | Some (Some prm) ->
        match Miou.await prm with
        | Ok () -> clean orphans
        | Error exn ->
            Log.err (fun m -> m "Unexpected exception from a task: %s"
              (Printexc.to_string exn));
            clean orphans

  let rec daemon state user's_outs n =
    clean state.orphans;
    let tcp, drops, outs = Utcp.timer state.tcp (now ()) in
    state.tcp <- tcp;
    let outs = List.rev_append user's_outs outs in
    let fn (_id, err, rcv, snd) =
      let err = match err with
        | `Retransmission_exceeded -> `Msg "retransmission exceeded"
        | `Timer_2msl -> `Eof
        | `Timer_connection_established -> `Eof
        | `Timer_fin_wait_2 -> `Eof in
      let err = Error err in
      ignore (Miou.Computation.try_return rcv err);
      ignore (Miou.Computation.try_return snd err) in
    List.iter fn drops;
    let fn out = ignore (Miou.async ~orphans:state.orphans @@ fun () ->
      try write_ip state.ipv4 out
      with
      | Net_unreach ->
        let (_, dst, _) = out in
        Log.err (fun m -> m "Network unreachable for %a" Ipaddr.pp dst)
      | exn ->
        let (src, dst, _) = out in
        Log.err (fun m -> m "Unexpected exception (%a -> %a): %s"
          Ipaddr.pp src Ipaddr.pp dst (Printexc.to_string exn))) in
    List.iter fn outs;
    let user's_outs = write_or_sync state in
    daemon state user's_outs (n+1)

  let create ~name ipv4 =
    let tcp = Utcp.empty Miou.Computation.create name Mirage_crypto_rng.generate in
    let mutex = Miou.Mutex.create () in
    let condition = Miou.Condition.create () in
    let orphans = Miou.orphans () in
    let state = { tcp; ipv4; queue= Queue.create (); mutex; condition; orphans } in
    let prm = Miou.async (fun () -> daemon state [] 0) in
    prm, state

  let kill = Miou.cancel

  let connect state (dst, dst_port) =
    let src = Ipaddr.V4 (IPv4.src state.ipv4) in
    let dst = Ipaddr.V4 dst in
    let tcp, flow, c, seg = Utcp.connect ~src ~dst ~dst_port state.tcp (now ()) in
    let src = Logs.Src.create (Fmt.str "%a:%d" Ipaddr.pp dst dst_port) in
    state.tcp <- tcp;
    write_ip state.ipv4 seg;
    Logs.debug ~src (fun m -> m "Waiting for a TCP handshake");
    match Miou.Computation.await_exn c with
    | Ok () -> { state; flow; src }
    | Error `Eof ->
        Logs.err ~src (fun m -> m "%a error established connection (timeout)" Utcp.pp_flow flow);
        raise Connection_refused
    | Error (`Msg msg) ->
        Logs.err ~src (fun m -> m "%a error established connection: %s" Utcp.pp_flow flow msg);
        raise Connection_refused
end
