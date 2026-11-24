-- Only used after the target is explicitly armed for one synthetic run.
INSERT INTO generations (id,bucket_id,key,state,size,etag,content_json,user_meta_json,extent_count,created_at)
SELECT gen, 'b_70676c6f61640001', key, 'live', width, '"pg-load"', '{}', '{}', width, 1
FROM load_seed WHERE family IN ('read','delete','outbox','post_mark','verify_record','gc','dispatch');
INSERT INTO objects (bucket_id,key,generation_id)
SELECT 'b_70676c6f61640001', key, gen FROM load_seed WHERE family IN ('read','delete','outbox','post_mark','verify_record');
UPDATE generations SET state='deleted',retired_at=1
WHERE bucket_id='b_70676c6f61640001' AND id IN (SELECT gen FROM load_seed WHERE family='gc');

INSERT INTO uploads (id,bucket_id,key,content_json,user_meta_json,state,revision,initiated_at)
SELECT upload,'b_70676c6f61640001',key,'{}','{}','open',
       CASE WHEN family='complete' THEN 1 ELSE 0 END,1
FROM load_seed WHERE family IN ('part','complete','abort');

INSERT INTO extents (id,bucket_id,generation_id,state,seq,plain_offset,plain_size,cipher_size,media_header,
                     wrapped_file_key,plain_md5,plain_sha256,cipher_sha256,safety_state,article_count,created_at)
SELECT CASE WHEN family='dispatch' THEN 'x_eeeeeeeeee'||lpad(to_hex(n*width+piece),16,'0') ELSE extent END,
       'b_70676c6f61640001', CASE WHEN family<>'complete' THEN gen END,
       CASE WHEN family='complete' THEN 'staged' ELSE 'committed' END,
       CASE WHEN family<>'complete' THEN piece END, CASE WHEN family<>'complete' THEN piece END,
       1,65,decode(repeat('00',48),'hex'),decode(repeat('00',73),'hex'),
       decode(repeat('00',16),'hex'),decode(repeat('00',32),'hex'),decode(repeat('00',32),'hex'),'held',
       CASE WHEN family='verify_record' THEN 1 END,1
FROM load_seed CROSS JOIN LATERAL generate_series(0,width-1) AS parts(piece)
WHERE family IN ('read','delete','outbox','post_mark','verify_record','gc','complete','dispatch');

INSERT INTO upload_parts (upload_id,part_number,extent_id,size,etag,uploaded_at)
SELECT upload,1,extent,1,'"pg-load"',1 FROM load_seed WHERE family='complete';
-- The inline first piece lives in upload_parts. upload_part_extents is only
-- for additional pieces (seq = first piece's seq + piece).

INSERT INTO outbox (extent_id,generation_id,stage,next_at,lease_token,lease_owner,lease_until,updated_at)
SELECT CASE WHEN family='dispatch' THEN 'x_eeeeeeeeee'||lpad(to_hex(n*width+piece),16,'0') ELSE extent END,
       gen,CASE WHEN family='read' THEN 'post' ELSE stage END,1,CASE WHEN held THEN 1 ELSE 0 END,
       CASE WHEN held THEN 'pg-load' END, CASE WHEN held THEN 8000000000000000 END,1
FROM load_seed CROSS JOIN LATERAL generate_series(0,width-1) AS parts(piece)
WHERE family IN ('outbox','post_mark','verify_record','read','dispatch');

INSERT INTO articles (extent_id,idx,message_id,newsgroup,headers,cipher_offset,cipher_len,payload_sha256,
                      state,provider_id,posted_at)
SELECT extent,0,extent||'@pg-load.invalid','pg-load',''::bytea,0,65,decode(repeat('00',32),'hex'),
       CASE WHEN family='verify_record' THEN 'posted' ELSE 'planned' END,
       CASE WHEN family='verify_record' THEN 'pg-load' END,
       CASE WHEN family='verify_record' THEN 1 END
FROM load_seed WHERE family IN ('post_mark','verify_record');

INSERT INTO gc (id,extent_id,action,due_at)
SELECT -n-1,extent,'delete_safety',1 FROM load_seed WHERE family='gc';

INSERT INTO provider_permits (provider_id,slot,token,holder,lease_until)
SELECT 'pg-load', n, CASE WHEN family='permit_release' THEN 1 ELSE 0 END,
       CASE WHEN family='permit_release' THEN 'pg-load' END,
       CASE WHEN family='permit_release' THEN 8000000000000000 ELSE 0 END
FROM load_seed WHERE family IN ('permit_acquire','permit_release');
