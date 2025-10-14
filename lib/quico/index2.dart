import 'dart:async';
import 'dart:core';
import 'dart:typed_data';

import 'quic_packet.dart';
import 'utils.dart';
enum ConnectionStatus{
  connecting,
  connected,
  disconnected,
}
class QuicConnection{
 ConnectionStatus connection_status;//: 4;//0 - connecting... | 1 - connected | 2 - disconnected | ...

  String? from_ip;
  int? from_port;//: null,

  int version;//: 1,

List<Uint8List>  my_cids= [];            // SCIDים שאתה נתת (כנראה אחד ראשוני ועוד future)
 List<Uint8List> their_cids= [];         // DCIDים שהצד השני השתמש בהם (כלומר שלך כשרת)
 Uint8List? original_dcid;//: null,     // ל־Initial ול־Retry

  //tls stuff...
 String? sni;//: null,

 int? tls_cipher_selected;//: null,
 int? tls_alpn_selected;//: null,

 List<int> tls_signature_algorithms= [];

 Uint8List? tls_handshake_secret;
Uint8List?  tls_shared_secret;
 Uint8List tls_early_secret;

 List<int> tls_transcript= [];
 int tls_handshake_step=0;
 bool tls_finished_ok= false;
  
 Uint8List? tls_server_public_key;
 Uint8List? tls_server_private_key;

 Uint8List? tls_client_handshake_traffic_secret;
 Uint8List? tls_server_handshake_traffic_secret;

 Uint8List? tls_client_app_traffic_secret;
 Uint8List? tls_server_app_traffic_secret;


  //....
  Uint8List? init_read_key;
  Uint8List? init_read_iv;
  Uint8List? init_read_hp;

  Uint8List? init_write_key;
  Uint8List? init_write_iv;
  Uint8List? init_write_hp;
  
  Uint8List? handshake_read_key;
  Uint8List? handshake_read_iv;
  Uint8List? handshake_read_hp;

  Uint8List? handshake_write_key;
  Uint8List? handshake_write_iv;
  Uint8List? handshake_write_hp;

   Uint8List? app_prev_read_key;
   Uint8List? app_prev_read_iv;
   Uint8List? app_prev_read_hp;
  
   Uint8List? app_read_key;
   Uint8List? app_read_iv;
   Uint8List? app_read_hp;

  bool read_key_phase= false;

   Uint8List? app_write_key;
   Uint8List? app_write_iv;
   Uint8List? app_write_hp;

  


  //sending...

  int sending_init_pn_next= 1;
 List<int> sending_init_chunks= [];
 int sending_init_offset_next= 0;
 List<int> sending_init_pn_acked_ranges= [];

 int sending_handshake_pn_next= 1;
  List<int> sending_handshake_chunks= [];
  int sending_handshake_offset_next= 0;
   List<int> sending_handshake_pn_acked_ranges= [];
  
  
 dynamic sending_streams= {};
 int sending_stream_id_next= 0;

  

 int max_sending_packets_per_sec= 1000;
 int max_sending_total_bytes_per_sec= 150000;
 int max_sending_packet_size= 1200;
 int min_sending_packet_size= 35;

 int max_sending_packets_in_flight= 20;
 int max_sending_bytes_in_flight= 150000;

 int sending_app_pn_base= 1;
 List<int> sending_app_pn_history= [];
 List<int> rtt_history= [];
 Set sending_app_pn_in_flight= Set();

 Timer? next_send_quic_packet_timer;
 bool sending_quic_packet_now= false;

  
  //received...

 int receiving_init_pn_largest= -1;
 List<int> receiving_init_pn_ranges= [];
dynamic  receiving_init_chunks= {};
 int receiving_init_from_offset= 0;
 List<int> receiving_init_ranges= [];//מערך שטוח של מ עד
  
int  receiving_handshake_pn_largest= -1;
List<int>  receiving_handshake_pn_ranges= [];
dynamic  receiving_handshake_chunks= {};
 int receiving_handshake_from_offset= 0;
 List<int> receiving_handshake_ranges= [];//מערך שטוח של מ עד

 int receiving_app_pn_largest= -1;
  List<int> receiving_app_pn_ranges= [];
  List<int> receiving_app_pn_history= [];

  List<int> receiving_app_pn_pending_ack= [];


dynamic  receiving_streams= {};           // stream_id → stream object
 Timer? receiving_streams_next_check_timer;


 int remote_ack_delay_exponent= 3;
 int remote_max_udp_payload_size= 1000;

 int? h3_remote_control_stream_id;
 int h3_remote_control_from_offset= 1;

 int? h3_remote_qpack_encoder_stream_id;
 int h3_remote_qpack_encoder_from_offset= 1;

int?  h3_remote_qpack_decoder_stream_id;
 int h3_remote_qpack_decoder_from_offset= 1;


 dynamic h3_http_request_streams= {};


 int h3_remote_max_header_size= 0;//מתקבל ב settings - אחרי פיענוח
 int h3_remote_qpack_max_table_capacity= 0;//מתקבל ב settings - גודל הטבלה המקסימלי
 bool? h3_remote_datagram_support;

 int h3_remote_qpack_table_base_index= 0;
 int h3_remote_qpack_table_capacity= 0;
 List<int> h3_remote_qpack_dynamic_table= [];


 dynamic h3_wt_sessions= {};
}

class QuicServer{
  Map<Uint8List,QuicConnection>connections={};
  
  Map<String,Uint8List> address_binds=[];
}

class Options{
  String? from_ip;
  int? from_port;
  int? version;
  Uint8List? dcid;
  Uint8List? scid;
  String? sni;
  ConnectionStatus? connection_status;
}

void set_quic_connection(QuicServer server, Uint8List quic_connection_id,Options options){
  bool is_modified=false;

  if(server.connections[quic_connection_id]==null){
    server.connections[quic_connection_id]=QuicConnection();

    is_modified=true;
  }

  final prev_params=(
    connection_status: server.connections[quic_connection_id]!.connection_status,
    sni: server.connections[quic_connection_id]!.sni
  );

  if(true){

    if( options.from_ip!=null){
      if(server.connections[quic_connection_id]!.from_ip!=options.from_ip){

        server.connections[quic_connection_id]!.from_ip=options.from_ip;
        is_modified=true;
      }
    }

    if(options.from_port!=null){
      if(server.connections[quic_connection_id]!.from_port!=options.from_port){

        server.connections[quic_connection_id]!.from_port=options.from_port;
        is_modified=true;
      }
    }

    if(options.version!=null){
      if(server.connections[quic_connection_id]!.version!=options.version){

        server.connections[quic_connection_id]!.version=options.version!;
        is_modified=true;
      }
    }

    
    if(options.dcid!=null && options.dcid!.isNotEmpty){
      if(server.connections[quic_connection_id]!.original_dcid==null || server.connections[quic_connection_id].original_dcid.byteLength<=0 || arraybufferEqual(options.dcid.buffer,server.connections[quic_connection_id].original_dcid.buffer)==false){

        server.connections[quic_connection_id]!.original_dcid=options.dcid;
        is_modified=true;
        
      }
    }


    if( options.scid!=null && options.scid!.isNotEmpty){

      var is_scid_exist=false;
      for(var i in server.connections[quic_connection_id]!.their_cids){
        if(arraybufferEqual(options.scid!,server.connections[quic_connection_id]!.their_cids[i])==true){
          is_scid_exist=true;
          break;
        }
      }

      if(is_scid_exist==false){
        server.connections[quic_connection_id]!.their_cids.add(options.scid!);
        is_modified=true;
      }
    }


    if(options.sni!=null){
      if(server.connections[quic_connection_id]!.sni!=options.sni){

        server.connections[quic_connection_id]!.sni=options.sni;
        is_modified=true;

      }
    }

    if(options.connection_status!=null){
      if(server.connections[quic_connection_id]!.connection_status!=options.connection_status){

        server.connections[quic_connection_id]!.connection_status=options.connection_status!;
        is_modified=true;

        //clean up...
        if(server.connections[quic_connection_id]!.connection_status==ConnectionStatus.connected){
          server.connections[quic_connection_id]!.tls_transcript=[];
          server.connections[quic_connection_id]!.receiving_init_chunks={};
          server.connections[quic_connection_id]!.receiving_handshake_chunks={};
        }


      }
    }


  }


  if(is_modified==true){
    
    var address_str = server.connections[quic_connection_id]!.from_ip! + ':' + server.connections[quic_connection_id]!.from_port.toString();
    if(address_str in server.address_binds==false || server.address_binds[address_str]!=quic_connection_id){

      server.address_binds[address_str]=quic_connection_id;
    }


    quic_connection(server,quic_connection_id,
      connection_status: server.connections[quic_connection_id]!.connection_status,
      sni: server.connections[quic_connection_id]!.sni
    ,prev_params: prev_params);

  }

  if(typeof options=='object'){

    

    if('cert' in options && 'key' in options){


      var cipher_info = get_cipher_info(server.connections[quic_connection_id].tls_cipher_selected);
      var hash_func = cipher_info.hash;





      var cert = new crypto.X509Certificate(options.cert);
      var cert_der = new Uint8Array(cert.raw);

      var certificate = build_certificate([{ cert: cert_der, extensions: new Uint8Array(0) }]);
      
      server.connections[quic_connection_id].tls_transcript.push(certificate);

      set_sending_quic_chunk(server,quic_connection_id,{
        type: 'handshake',
        data: certificate
      });

      //////////////////////////////////


      
      var privateKeyObj = crypto.createPrivateKey(options.key);

      
      var label = new TextEncoder().encode("TLS 1.3, server CertificateVerify");
      var separator = new Uint8Array([0x00]);
      var handshake_hash = hash_transcript(server.connections[quic_connection_id].tls_transcript,hash_func); // SHA-256 over transcript

      // padding של 64 תווי רווח
      var padding = new Uint8Array(64).fill(0x20);

      // בניית signed_data לפי הפורמט
      var signed_data = new Uint8Array(
          padding.length + label.length + separator.length + handshake_hash.length
      );
      signed_data.set(padding, 0);
      signed_data.set(label, padding.length);
      signed_data.set(separator, padding.length + label.length);
      signed_data.set(handshake_hash, padding.length + label.length + separator.length);

      // מיפוי סוגי מפתח לאלגוריתמים תקניים
      var ALGO_BY_TYPE = {
          'rsa': 0x0804,       // rsa_pss_rsae_sha256
          'ec': 0x0403,        // ecdsa_secp256r1_sha256
          'ed25519': 0x0807    // ed25519
      };

      var keyType = privateKeyObj.asymmetricKeyType;
      var algo_candidate = ALGO_BY_TYPE[keyType];

      if (!algo_candidate) {
          throw new Error("Unsupported private key type for TLS 1.3 CertificateVerify: " + keyType);
      }

      if (!server.connections[quic_connection_id].tls_signature_algorithms.includes(algo_candidate)) {
          throw new Error(`Client did not offer compatible signature algorithm for key type ${keyType}`);
      }

      var signature=null;

      if (keyType === 'rsa') {
          signature = new Uint8Array(crypto.sign('sha256', Buffer.from(signed_data), 
              {
                  key: privateKeyObj,
                  padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                  saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST // 32 bytes for SHA256
              }
          ));
      } else if (keyType === 'ec') {
          signature = new Uint8Array(crypto.sign('sha256', Buffer.from(signed_data), privateKeyObj));
      } else if (keyType === 'ed25519') {
          signature = new Uint8Array(crypto.sign(null, Buffer.from(signed_data), privateKeyObj));
      }

      var cert_verify = build_certificate_verify(algo_candidate, signature);
      
      server.connections[quic_connection_id].tls_transcript.push(cert_verify);

      set_sending_quic_chunk(server,quic_connection_id,{
        type: 'handshake',
        data: cert_verify
      });

      /////////////////////////////////
      var finished_key = hkdf_expand_label(server.connections[quic_connection_id].tls_server_handshake_traffic_secret, 'finished', new Uint8Array(), hash_func.outputLen,hash_func);

      var verify_data = hmac(cipher_info.str, finished_key, hash_transcript(server.connections[quic_connection_id].tls_transcript,hash_func));

      var finished = build_finished(verify_data);
      server.connections[quic_connection_id].tls_transcript.push(finished);

      set_sending_quic_chunk(server,quic_connection_id,{
        type: 'handshake',
        data: finished
      });
      //////////////////////////////


      var c = tls_derive_app_secrets(server.connections[quic_connection_id].tls_handshake_secret, server.connections[quic_connection_id].tls_transcript, hash_func);

      server.connections[quic_connection_id].tls_client_app_traffic_secret = c.client_application_traffic_secret;

      server.connections[quic_connection_id].tls_server_app_traffic_secret = c.server_application_traffic_secret;

    }

    

    if('incoming_packet' in options){

      if('type' in options['incoming_packet']){

        var read_key=null;
        var read_iv=null;
        var read_hp=null;

        var largest_pn=-1;

        if(options['incoming_packet']['type']=='initial'){

          if(server.connections[quic_connection_id].init_read_key!==null && server.connections[quic_connection_id].init_read_iv!==null && server.connections[quic_connection_id].init_read_hp!==null){
            read_key=server.connections[quic_connection_id].init_read_key;
            read_iv=server.connections[quic_connection_id].init_read_iv;
            read_hp=server.connections[quic_connection_id].init_read_hp;

          }else{
            var d = quic_derive_init_secrets(server.connections[quic_connection_id].original_dcid,server.connections[quic_connection_id].version,'read');

            read_key=d.key;
            read_iv=d.iv;
            read_hp=d.hp;

            server.connections[quic_connection_id].init_read_key=d.key;
            server.connections[quic_connection_id].init_read_iv=d.iv;
            server.connections[quic_connection_id].init_read_hp=d.hp;
          }

          largest_pn=Number(server.connections[quic_connection_id].receiving_init_pn_largest)+0;

        }else if(options['incoming_packet']['type']=='handshake'){

          if(server.connections[quic_connection_id].handshake_read_key!==null && server.connections[quic_connection_id].handshake_read_iv!==null && server.connections[quic_connection_id].handshake_read_hp!==null){
            read_key=server.connections[quic_connection_id].handshake_read_key;
            read_iv=server.connections[quic_connection_id].handshake_read_iv;
            read_hp=server.connections[quic_connection_id].handshake_read_hp;

          }else if(server.connections[quic_connection_id].tls_client_handshake_traffic_secret!==null){
            var d = quic_derive_from_tls_secrets(server.connections[quic_connection_id].tls_client_handshake_traffic_secret,sha256);

            read_key=d.key;
            read_iv=d.iv;
            read_hp=d.hp;

            server.connections[quic_connection_id].handshake_read_key=d.key;
            server.connections[quic_connection_id].handshake_read_iv=d.iv;
            server.connections[quic_connection_id].handshake_read_hp=d.hp;

          }

          largest_pn=Number(server.connections[quic_connection_id].receiving_handshake_pn_largest)+0;

        }else if(options['incoming_packet']['type']=='1rtt'){

          
          if(server.connections[quic_connection_id].app_read_key!==null && server.connections[quic_connection_id].app_read_iv!==null && server.connections[quic_connection_id].app_read_hp!==null){
            read_key=server.connections[quic_connection_id].app_read_key;
            read_iv=server.connections[quic_connection_id].app_read_iv;
            read_hp=server.connections[quic_connection_id].app_read_hp;

          }else if(server.connections[quic_connection_id].tls_client_app_traffic_secret!==null){

            var d = quic_derive_from_tls_secrets(server.connections[quic_connection_id].tls_client_app_traffic_secret,sha256);

            read_key=d.key;
            read_iv=d.iv;
            read_hp=d.hp;

            server.connections[quic_connection_id].app_read_key=d.key;
            server.connections[quic_connection_id].app_read_iv=d.iv;
            server.connections[quic_connection_id].app_read_hp=d.hp;
            

            
            
          }

          largest_pn=Number(server.connections[quic_connection_id].receiving_app_pn_largest)+0;
          
        }

        if(read_key!==null && read_iv!==null){

          var decrypted_packet = decrypt_quic_packet(options['incoming_packet']['data'], read_key, read_iv, read_hp,server.connections[quic_connection_id].original_dcid,largest_pn);

          if(decrypted_packet && decrypted_packet.plaintext!==null && decrypted_packet.plaintext.byteLength>0){

            /*
            if(server.connections[quic_connection_id].read_key_phase!==options['incoming_packet'].key_phase){
              console.log('changed key pashe!!!!!!!!!!!!!!!!!!! '+options['incoming_packet'].key_phase);
              server.connections[quic_connection_id].read_key_phase=options['incoming_packet'].key_phase;
            }
            */

            //console.log('key phase: ',decrypted_packet.key_phase);


            var need_check_tls_chunks=false;
            var is_new_packet=false;

            var need_check_receiving_streams=false;
            

            if(options['incoming_packet']['type']=='initial'){

              is_new_packet=flat_ranges.add(server.connections[quic_connection_id].receiving_init_pn_ranges, [decrypted_packet.packet_number,decrypted_packet.packet_number]);

              if(server.connections[quic_connection_id].receiving_init_pn_largest<decrypted_packet.packet_number){
                server.connections[quic_connection_id].receiving_init_pn_largest=decrypted_packet.packet_number;
              }

            }else if(options['incoming_packet']['type']=='handshake'){

              is_new_packet=flat_ranges.add(server.connections[quic_connection_id].receiving_handshake_pn_ranges, [decrypted_packet.packet_number,decrypted_packet.packet_number]);

              if(server.connections[quic_connection_id].receiving_handshake_pn_largest<decrypted_packet.packet_number){
                server.connections[quic_connection_id].receiving_handshake_pn_largest=decrypted_packet.packet_number;
              }

            }else if(options['incoming_packet']['type']=='1rtt'){

              is_new_packet=flat_ranges.add(server.connections[quic_connection_id].receiving_app_pn_ranges, [decrypted_packet.packet_number,decrypted_packet.packet_number]);

              if(server.connections[quic_connection_id].receiving_app_pn_largest<decrypted_packet.packet_number){
                server.connections[quic_connection_id].receiving_app_pn_largest=decrypted_packet.packet_number;

                //console.log(server.connections[quic_connection_id].receiving_app_pn_ranges);
              }

              if(server.connections[quic_connection_id].connection_status!==1){
               

                set_quic_connection(server,quic_connection_id,{
                  connection_status: 1
                });
              }

            }
            
            if(is_new_packet==true){

              var ack_eliciting=false;

              var frames=parse_quic_frames(decrypted_packet.plaintext);

              for(var i in frames){
                
                if(ack_eliciting==false && (frames[i].type=='stream' || frames[i].type=='crypto' || frames[i].type=='new_connection_id' || frames[i].type=='handshake_done' || frames[i].type=='path_challenge' || frames[i].type=='path_response' || frames[i].type=='ping')){
                  ack_eliciting=true;
                }



                if(options['incoming_packet']['type']=='handshake'){
                  //console.log('handshake get! ..@@@@@@@@@@@@.');
                  //console.log(frames[i]);
                }else if(options['incoming_packet']['type']=='1rtt'){
                  //console.log('1rtt get! ..@@@@@@@@@@@@.');
                  //console.log(frames[i]);
                }
                

                if(frames[i].type=='crypto'){
                  if(options['incoming_packet']['type']=='initial'){

                    if(flat_ranges.add(server.connections[quic_connection_id].receiving_init_ranges, [frames[i].offset, frames[i].offset + frames[i].data.length])==true){

                      if(frames[i].offset in server.connections[quic_connection_id].receiving_init_chunks==false || server.connections[quic_connection_id].receiving_init_chunks[frames[i].offset].byteLength<frames[i].data.byteLength){
                        server.connections[quic_connection_id].receiving_init_chunks[frames[i].offset]=frames[i].data;
                      }
                      
                      need_check_tls_chunks=true;

                    }

                  }else if(options['incoming_packet']['type']=='handshake'){

                    if(flat_ranges.add(server.connections[quic_connection_id].receiving_handshake_ranges, [frames[i].offset, frames[i].offset + frames[i].data.length])==true){

                      

                      if(frames[i].offset in server.connections[quic_connection_id].receiving_handshake_chunks==false || server.connections[quic_connection_id].receiving_handshake_chunks[frames[i].offset].byteLength<frames[i].data.byteLength){
                        server.connections[quic_connection_id].receiving_handshake_chunks[frames[i].offset]=frames[i].data;
                      }
                      
                      need_check_tls_chunks=true;

                    }

                  }
                }else if(frames[i].type=='stream'){

                  if(frames[i].id in server.connections[quic_connection_id].receiving_streams==false){
                    server.connections[quic_connection_id].receiving_streams[frames[i].id]={
                      receiving_chunks: {},
                      total_size: 0,
                      receiving_ranges: [],
                      need_check: false
                    };
                  }

                  if(flat_ranges.add(server.connections[quic_connection_id].receiving_streams[frames[i].id].receiving_ranges, [frames[i].offset, frames[i].offset + frames[i].data.length])==true){
                    
                    if(frames[i].offset in server.connections[quic_connection_id].receiving_streams[frames[i].id].receiving_chunks==false || server.connections[quic_connection_id].receiving_streams[frames[i].id].receiving_chunks[frames[i].offset].byteLength<frames[i].data.byteLength){
                      server.connections[quic_connection_id].receiving_streams[frames[i].id].receiving_chunks[frames[i].offset]=frames[i].data;
                    }

                    if('fin' in frames[i] && frames[i].fin==true){
                      server.connections[quic_connection_id].receiving_streams[frames[i].id].total_size=frames[i].data.byteLength+frames[i].offset;
                    }

                    server.connections[quic_connection_id].receiving_streams[frames[i].id].need_check=true;

                    if(need_check_receiving_streams==false){
                      need_check_receiving_streams=true;
                    }

                  }

                }else if(frames[i].type=='stop_sending'){

                  //console.log(frames[i]);
                  //console.log('stop_sending!!!!!!!!!!!');

                }else if(frames[i].type=='datagram'){

                  var wt_datagram=parse_webtransport_datagram(frames[i].data);
                  if(wt_datagram.stream_id in server.connections[quic_connection_id].h3_wt_sessions){
                    var session = server.connections[quic_connection_id].h3_wt_sessions[wt_datagram.stream_id];
                    if (typeof session.ondatagram === 'function') {
                      session.ondatagram(wt_datagram.data); // מעביר רק את התוכן
                    }
                  }

                }else if(frames[i].type=='ack'){
                  

                  if(options['incoming_packet']['type']=='initial'){

                    var acked_ranges=quic_acked_info_to_ranges(frames[i]);

                    if(flat_ranges.add(server.connections[quic_connection_id].sending_init_pn_acked_ranges, acked_ranges)==true){
                      //console.log(server.connections[quic_connection_id].sending_init_pn_acked_ranges);
                    }

                  }else if(options['incoming_packet']['type']=='handshake'){

                    var acked_ranges=quic_acked_info_to_ranges(frames[i]);

                    if(flat_ranges.add(server.connections[quic_connection_id].sending_handshake_pn_acked_ranges, acked_ranges)==true){
                      //console.log(server.connections[quic_connection_id].sending_handshake_pn_acked_ranges);
                    }

                  }else if(options['incoming_packet']['type']=='1rtt'){

                    process_ack_frame(server,quic_connection_id,frames[i]);

                  }


                }else{
                  //console.log(frames[i]);
                }

                
              }

              //console.log('get frames:');
              //console.log(frames);


              if(options['incoming_packet']['type']=='1rtt'){
                //add to history
                var now=Math.floor(performance.timeOrigin + performance.now());
                server.connections[quic_connection_id].receiving_app_pn_history.push([decrypted_packet.packet_number,now,options['incoming_packet']['data'].byteLength]);
              }

              if(ack_eliciting==true){
                var ack_frame_to_send = [];

                if(options['incoming_packet']['type']=='initial'){
                  ack_frame_to_send.push(build_ack_info_from_ranges(server.connections[quic_connection_id].receiving_init_pn_ranges, null, 0));
                }else if(options['incoming_packet']['type']=='handshake'){
                  ack_frame_to_send.push(build_ack_info_from_ranges(server.connections[quic_connection_id].receiving_handshake_pn_ranges, null, 0));
                }else if(options['incoming_packet']['type']=='1rtt'){

                  flat_ranges.add(server.connections[quic_connection_id].receiving_app_pn_pending_ack, [decrypted_packet.packet_number,decrypted_packet.packet_number]);

                  prepare_and_send_quic_packet(server,quic_connection_id);
                  
                }


                if(ack_frame_to_send.length>0){
                  send_quic_frames_packet(server,quic_connection_id,options['incoming_packet']['type'],ack_frame_to_send);
                }
              }


              
              
            }


            var tls_messages=[];

            if(need_check_tls_chunks==true){
              if(options['incoming_packet']['type']=='initial'){
                
                var ext=extract_tls_messages_from_chunks(server.connections[quic_connection_id].receiving_init_chunks, server.connections[quic_connection_id].receiving_init_from_offset);
                
                tls_messages=ext.tls_messages;

                server.connections[quic_connection_id].receiving_init_from_offset=ext.new_from_offset;

              }else if(options['incoming_packet']['type']=='handshake'){

                var ext=extract_tls_messages_from_chunks(server.connections[quic_connection_id].receiving_handshake_chunks, server.connections[quic_connection_id].receiving_handshake_from_offset);
                
                tls_messages=ext.tls_messages;

                server.connections[quic_connection_id].receiving_handshake_from_offset=ext.new_from_offset;

              }
            }


            if(tls_messages.length>0){
              for(var i in tls_messages){
                process_quic_tls_message(server,quic_connection_id,tls_messages[i]);
              }
            }

            if(need_check_receiving_streams==true){
              
              if(server.connections[quic_connection_id].receiving_streams_next_check_timer==null){
                
                //run timer...
                server.connections[quic_connection_id].receiving_streams_next_check_timer=setTimeout(function(){
                  server.connections[quic_connection_id].receiving_streams_next_check_timer=null;
                  process_quic_receiving_streams(server,quic_connection_id);
                },5);

              }

            }


            

          }else{

            //console.log('decrtyped packet fail...');

          }
        }


        

      }

    }
  }
}
