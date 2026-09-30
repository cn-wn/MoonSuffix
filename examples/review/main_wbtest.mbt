///|
test "one-minute review reports the actual boundary and Cookie change" {
  assert_eq(
    review_report(),
    "lookup api.shop.example.co.uk: suffix=co.uk, registrable=example.co.uk\n" +
    "PSL update: +PRIVATE glideos.app\n" +
    "api.glideos.app: registrable glideos.app -> api.glideos.app\n" +
    "Cookie Domain=.glideos.app: glideos.app accepted -> cookie Domain attribute 'glideos.app' is a public suffix\n" +
    "changed hosts=1, changed Cookie scopes=1",
  )
}
