type keys
type session_id
type ssl

type state =
| Success
| RequestSend
| RequestRecv
| HandshakeComplete
| ReceivedAlert of int * int
| AppData of string

let string_of_state = function
  | Success -> "Success"
  | RequestSend -> "RequestSend"
  | RequestRecv -> "RequestRecv"
  | HandshakeComplete -> "HandshakeComplete"
  | ReceivedAlert (x,y) -> Printf.sprintf "ReceivedAlert (%d,%d)" x y
  | AppData s -> Printf.sprintf "AppData (%d)" (String.length s)

external _open : unit -> int = "stub_core_open"
external close : unit -> unit = "stub_core_close"
external new_keys : unit -> keys = "stub_new_keys"
external delete_keys : keys -> unit = "stub_delete_keys"
external load_rsa_keys : keys -> string -> string -> string -> unit = "stub_load_rsa_keys_mem"
external new_session_id : unit -> session_id = "stub_new_session_id"
external clear_session_id : session_id -> unit = "stub_clear_session_id"
external delete_session_id : session_id -> unit = "stub_delete_session_id"
external new_client_session : keys -> session_id -> int -> int -> int -> int -> int -> ssl = "stub_new_client_session_bc" "stub_new_client_session_native"
external get_out_data : ssl -> string = "stub_get_out_data"
external sent_data : ssl -> int -> state = "stub_sent_data"
external received_data : ssl -> string -> state = "stub_received_data"
external processed_data : ssl -> state = "stub_processed_data"
external encode_data : ssl -> string -> int = "stub_encode_data"
