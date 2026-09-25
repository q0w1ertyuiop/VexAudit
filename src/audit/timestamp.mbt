///|
priv struct Timestamp {
  seconds : Int64
  fraction : Array[Char]
}

///|
fn digits(chars : Array[Char], start : Int, count : Int) -> Int? {
  if start + count > chars.length() {
    return None
  }
  let mut value = 0
  for index = start; index < start + count; index = index + 1 {
    let char = chars[index]
    if char < '0' || char > '9' {
      return None
    }
    value = value * 10 + char.to_int() - '0'.to_int()
  }
  Some(value)
}

///|
fn leap_year(year : Int) -> Bool {
  year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

///|
fn month_length(year : Int, month : Int) -> Int {
  match month {
    2 => if leap_year(year) { 29 } else { 28 }
    4 | 6 | 9 | 11 => 30
    _ => 31
  }
}

///|
fn days_before_year(year : Int) -> Int {
  let previous = year - 1
  365 * previous + previous / 4 - previous / 100 + previous / 400
}

///|
fn parse_timestamp(value : String) -> Timestamp? {
  let chars = value.to_array()
  if chars.length() < 20 ||
    chars[4] != '-' ||
    chars[7] != '-' ||
    (chars[10] != 'T' && chars[10] != 't') ||
    chars[13] != ':' ||
    chars[16] != ':' {
    return None
  }
  guard digits(chars, 0, 4) is Some(year) else { return None }
  guard digits(chars, 5, 2) is Some(month) else { return None }
  guard digits(chars, 8, 2) is Some(day) else { return None }
  guard digits(chars, 11, 2) is Some(hour) else { return None }
  guard digits(chars, 14, 2) is Some(minute) else { return None }
  guard digits(chars, 17, 2) is Some(second) else { return None }
  if year < 1 ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > month_length(year, month) ||
    hour > 23 ||
    minute > 59 ||
    second > 59 {
    return None
  }
  let fraction : Array[Char] = []
  let mut zone_index = 19
  if zone_index < chars.length() && chars[zone_index] == '.' {
    zone_index = zone_index + 1
    while zone_index < chars.length() &&
          chars[zone_index] >= '0' &&
          chars[zone_index] <= '9' {
      fraction.push(chars[zone_index])
      zone_index = zone_index + 1
    }
    if fraction.is_empty() {
      return None
    }
  }
  let mut offset_minutes = 0
  if zone_index + 1 == chars.length() &&
    (chars[zone_index] == 'Z' || chars[zone_index] == 'z') {
    ()
  } else if zone_index + 6 == chars.length() &&
    (chars[zone_index] == '+' || chars[zone_index] == '-') &&
    chars[zone_index + 3] == ':' {
    guard digits(chars, zone_index + 1, 2) is Some(offset_hour) else {
      return None
    }
    guard digits(chars, zone_index + 4, 2) is Some(offset_minute) else {
      return None
    }
    if offset_hour > 23 || offset_minute > 59 {
      return None
    }
    offset_minutes = offset_hour * 60 + offset_minute
    if chars[zone_index] == '-' {
      offset_minutes = -offset_minutes
    }
  } else {
    return None
  }
  let mut days = days_before_year(year) - days_before_year(1970)
  for previous_month = 1
      previous_month < month
      previous_month = previous_month + 1 {
    days = days + month_length(year, previous_month)
  }
  days = days + day - 1
  let seconds = days.to_int64() * 86400L +
    hour.to_int64() * 3600L +
    minute.to_int64() * 60L +
    second.to_int64() -
    offset_minutes.to_int64() * 60L
  Some({ seconds, fraction, })
}

///| Parse the RFC 3339 timestamp profile used for statement ordering.

///|
/// Leap-second notation is rejected because it needs external leap-second data.
pub fn valid_timestamp(value : String) -> Bool {
  parse_timestamp(value) is Some(_)
}

///| Return -1, 0, or 1 when both timestamps are valid, or None otherwise.

///|
/// Offsets are normalized before fractional seconds are compared.
pub fn timestamp_order(left : String, right : String) -> Int? {
  guard parse_timestamp(left) is Some(a) else { return None }
  guard parse_timestamp(right) is Some(b) else { return None }
  if a.seconds < b.seconds {
    return Some(-1)
  }
  if a.seconds > b.seconds {
    return Some(1)
  }
  let count = if a.fraction.length() > b.fraction.length() {
    a.fraction.length()
  } else {
    b.fraction.length()
  }
  for index = 0; index < count; index = index + 1 {
    let left_digit = if index < a.fraction.length() {
      a.fraction[index]
    } else {
      '0'
    }
    let right_digit = if index < b.fraction.length() {
      b.fraction[index]
    } else {
      '0'
    }
    if left_digit < right_digit {
      return Some(-1)
    }
    if left_digit > right_digit {
      return Some(1)
    }
  }
  Some(0)
}
