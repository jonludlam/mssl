let string_of_file fname =
  let ic = open_in fname in
  let b = Buffer.create 0x10000 in
  let buff = String.create 0x1000 in
  let rec copy () =
    let n = input ic buff 0 0x1000 in
    if n = 0 then Buffer.contents b else
      (Buffer.add_substring b buff 0 n; copy())
  in copy()

let rec really_write sock str =
  let written = Unix.write sock str 0 (String.length str) in
  if written < String.length str then
    really_write sock (String.sub str written (String.length str - written))
  else ()

let rec do_it sock ssl state =
  Printf.printf "state=%s\n%!" (Mssl.string_of_state state);
  match state with
  | Mssl.Success -> state
  | Mssl.RequestSend ->
    let data = Mssl.get_out_data ssl in
    Printf.printf "Got %d bytes to send\n%!" (String.length data);
    really_write sock data;
    let new_state = Mssl.sent_data ssl (String.length data) in
    let new_state = if new_state = Mssl.Success then Mssl.RequestRecv else new_state in
    do_it sock ssl new_state
  | Mssl.RequestRecv ->
    let buf = String.create 1000 in
    let len = Unix.read sock buf 0 1000 in
    let str = String.sub buf 0 len in
    let new_state = Mssl.received_data ssl str in
    do_it sock ssl new_state
  | Mssl.HandshakeComplete ->
    Printf.printf "handshake complete\n%!";
    state
  | Mssl.AppData s ->
    Printf.printf "'%s'\n%!" s;
    let new_state = Mssl.processed_data ssl in
    do_it sock ssl new_state
  | Mssl.ReceivedAlert (_,_) ->
    Printf.printf "Received alert\n%!";
    state
    
    
let _ =
  let sock = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let sockaddr = Unix.ADDR_INET (Unix.inet_addr_of_string "192.168.53.131", 443) in
  Unix.connect sock sockaddr;

	let res = Mssl._open () in
	let keys = Mssl.new_keys () in
	let sess = Mssl.new_session_id () in
	let f = string_of_file Sys.argv.(1) in
	Mssl.load_rsa_keys keys "" "" f;
	let ssl = Mssl.new_client_session keys sess 0 0 0 0 0 in
	let state = do_it sock ssl Mssl.RequestSend in
	if state = Mssl.HandshakeComplete then begin
	  let msg = "GET / http/1.0\r\n\r\n" in
	  let len = Mssl.encode_data ssl msg in
	  ignore(do_it sock ssl Mssl.RequestSend)
	end;
    do_it sock ssl Mssl.RequestRecv

					      

