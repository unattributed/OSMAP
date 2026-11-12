use super::*;
#[test]
fn after_archive_settings_cas_csrf_owner_and_confirmed_navigation(){
 for (ua,uid,next,status) in [("Firefox/Test",10,true,303),("Firefox/Test",9,false,303),("ReadingUnavailable",10,false,303),("OSMAP/LegacyMetadata",10,false,303),("WelcomeData/wrong-owner",10,false,303),("MoveUnknown",10,false,503)] {
  let root=temp_dir("after-archive-routes");let prefs=crate::after_archive::Store::new(root.join("settings"));
  let app=BrowserApp::new(HttpPolicy::default(),StubGateway{after_archive_store:Some(prefs.clone()),settings_store:Some(crate::settings::FileUserSettingsStore::new(root.join("settings"))),snooze_store:Some(crate::snooze::SnoozeStore::new(root.join("settings"))),..StubGateway::default()});
  let csrf=StubGateway::validated_session().record.csrf_token;
  let post=|path:&str,body:&str|{let mut r=request("POST",path,&authenticated_same_origin_headers(),body);r.headers.insert("user-agent".into(),ua.into());app.handle_request(&r,"127.0.0.1")};
  let form=format!("csrf_token={csrf}&revision=0&choice=next");assert_eq!(post("/settings/after-archive",&form.replace(&csrf,"bad")).response.status_code,403);assert_eq!(post("/settings/after-archive",&form).response.status_code,303);assert_eq!(post("/settings/after-archive",&form.replace("choice=next","choice=list")).response.status_code,409);assert_eq!(prefs.load("bob@example.com").unwrap().choice,crate::after_archive::Choice::List);
  assert_eq!(post("/settings",&format!("csrf_token={csrf}&settings_action=archive&return_section=copies&archive_mailbox_name=INBOX.Projects")).response.status_code,303);
  let moved=post("/message/move",&move_form(&format!("csrf_token={csrf}&mailbox=INBOX&uid={uid}"),"archive"));assert_eq!(moved.response.status_code,status,"{ua}: {}",body_text(&moved));
  if status==303 {let location=location_header(&moved);assert_eq!(location.starts_with("/message?"),next,"{ua}: {location}");if next{assert!(location.contains("uid=9&mailbox_guid="));assert!(location.contains("return_to="));}}
  fs::remove_dir_all(root).unwrap();
 }
}
