(*
 * Copyright (c) 2012-2014 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c) 2014 Clark Gaebel
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
*)

open Core.Std
open Async.Std
open Async_ssl.Std

let ssl_connect ?version ?name ?ca_file ?ca_path ?session ?verify r w =
  let net_to_ssl = Reader.pipe r in
  let ssl_to_net = Writer.pipe w in
  let app_to_ssl, app_wr = Pipe.create () in
  let app_rd, ssl_to_app = Pipe.create () in
  let verify_connection = match verify with
    | None -> Fn.const (return true)
    | Some f -> f
  in
  Ssl.client
    ?version
    ?name
    ?ca_file
    ?ca_path
    ?session
    ~app_to_ssl
    ~ssl_to_app
    ~net_to_ssl
    ~ssl_to_net
    ()
  |> Deferred.Or_error.ok_exn
  >>= fun conn ->
  verify_connection conn >>= function
  | false ->
    Ssl.Connection.close conn ;
    Pipe.close_read app_rd ;
    Writer.close w >>= fun () ->
    failwith "Connection verification failed."
  | true ->
    Reader.of_pipe (Info.of_string "async_conduit_ssl_reader") app_rd >>= fun app_reader ->
    Writer.of_pipe (Info.of_string "async_conduit_ssl_writer") app_wr >>| fun (app_writer,_) ->
    don't_wait_for begin
      Deferred.all_unit [
        Writer.close_finished app_writer ;
        Reader.close_finished app_reader ;
      ] >>= fun () ->
      Ssl.Connection.close conn ;
      Pipe.close_read app_rd ;
      Writer.close w ;
    end ;
    (app_reader, app_writer)

let ssl_listen ?(version=Ssl.Version.Tlsv1_2) ?ca_file ?ca_path ~crt_file ~key_file r w =
  let net_to_ssl = Reader.pipe r in
  let ssl_to_net = Writer.pipe w in
  let app_to_ssl, app_wr = Pipe.create () in
  let app_rd, ssl_to_app = Pipe.create () in
  Ssl.server
    ?ca_file
    ?ca_path
    ~version
    ~crt_file
    ~key_file
    ~app_to_ssl
    ~ssl_to_app
    ~net_to_ssl
    ~ssl_to_net
    ()
  |> Deferred.Or_error.ok_exn
  >>= fun conn ->
  Reader.of_pipe (Info.of_string "async_conduit_ssl_reader") app_rd >>= fun app_reader ->
  Writer.of_pipe (Info.of_string "async_conduit_ssl_writer") app_wr >>| fun (app_writer,_) ->
  don't_wait_for begin
    Deferred.all_unit [
      Reader.close_finished app_reader;
      Writer.close_finished app_writer
    ] >>= fun () ->
    Ssl.Connection.close conn ;
    Pipe.close_read app_rd ;
    Writer.close w ;
  end;
  (app_reader, app_writer)
