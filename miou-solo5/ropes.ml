let src = Logs.Src.create "ropes"

module Log = (val Logs.src_log src : Logs.LOG)

type fix = |
type unknown = |

type 'a t =
  | Str : string -> fix t
  | Unknown : 'a size -> 'a t
  | App : fix t * 'a t * int * 'a size -> 'a t
and 'a size =
  | Length : int -> fix size
  | Limitless : unknown size

let ( <+> ) : type a. a size -> int -> a size = function
  | Length a -> fun b -> Length (a + b)
  | Limitless -> fun _ -> Limitless

let length : type a. a t -> a size = function
  | Unknown v ->  v
  | Str str -> Length (String.length str)
  | App (_, _, _, Limitless) -> Limitless
  | App (_, _, ls, rs) -> rs <+> ls

exception Out_of_bounds
exception Overlap

let () = Printexc.register_printer @@ function
  | Out_of_bounds -> Some "Fragment out of bounds"
  | Overlap -> Some "Fragment overlap"
  | _ -> None

let rec insert
  : type a. off:int -> string -> a t -> a t
  = fun ~off str -> function
  | Unknown Limitless ->
      let l = Unknown (Length off) in
      let rl = Str str in
      let rr = Unknown Limitless in
      App (l, App (rl, rr, String.length str, Limitless), off, Limitless)
  | Unknown (Length top) ->
      if off < 0
      || off > top - String.length str
      then raise_notrace Out_of_bounds;
      if off + String.length str == top
      then
        let l = Unknown (Length off) in
        let r = Str str in
        App (l, r, off, Length (String.length str))
      else
        let l = Unknown (Length off) in
        let rl = Str str in
        let rrs = Length (top - off - String.length str) in
        let rr = Unknown rrs in
        let rs = rrs <+> String.length str in
        App (l, App (rl, rr, String.length str, rrs), off, rs)
  | App (l, r, ls, rs) ->
      if off < ls
      then App (insert ~off str l, r, ls, rs)
      else
        let r = insert ~off:(off - ls) str r in
        let rs = length r in
        App (l, r, ls, rs)
  | Str _ -> raise_notrace Overlap

let rec fix : max:int -> unknown t -> fix t
  = fun ~max -> function
  | Unknown Limitless -> Unknown (Length max)
  | App (l, r, ls, Limitless) ->
      let r = fix ~max:(max - ls) r in
      let rs = length r in
      App (l, r, ls, rs)

let to_bytes : fix t -> Diet.t * bytes = fun t ->
  let Length len = length t in
  let buf = Bytes.create len in
  let rec go diet off = function
    | Str str -> 
      let len = String.length str in
      Bytes.blit_string str 0 buf off len;
      Log.debug (fun m -> m "+[%d, %d]" off (off + len));
      Diet.add ~off ~len diet
    | Unknown (Length 0) -> diet
    | Unknown (Length len) ->
      Bytes.fill buf off len '\000';
      Log.debug (fun m -> m "+[%d, %d] (unknown)" off (off + len));
      Diet.add ~off ~len diet
    | App (l, r, ls, _) ->
      let diet = go diet off l in
      go diet (off + ls) r in
  let diet = go Diet.empty 0 t in diet, buf
