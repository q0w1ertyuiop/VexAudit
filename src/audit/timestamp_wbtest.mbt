///|
test "RFC 3339 offsets refer to the same instant" {
  assert_eq(
    timestamp_order("2026-09-25T03:00:00+03:00", "2026-09-25T00:00:00Z"),
    Some(0),
  )
  assert_eq(
    timestamp_order("2026-09-24T19:00:00-05:00", "2026-09-25T00:00:00Z"),
    Some(0),
  )
}

///|
test "fractional precision orders successive claims" {
  assert_eq(
    timestamp_order(
      "2026-09-25T00:00:00.000000002Z", "2026-09-25T00:00:00.000000001Z",
    ),
    Some(1),
  )
  assert_eq(
    timestamp_order("2026-09-25T00:00:00.10Z", "2026-09-25T00:00:00.1Z"),
    Some(0),
  )
}

///|
test "invalid calendar dates and offsets are rejected" {
  assert_eq(valid_timestamp("2026-02-29T00:00:00Z"), false)
  assert_eq(valid_timestamp("2024-02-29T00:00:00Z"), true)
  assert_eq(valid_timestamp("2026-09-25T00:00:00+24:00"), false)
  assert_eq(valid_timestamp("2026-09-25T00:00:60Z"), false)
}
