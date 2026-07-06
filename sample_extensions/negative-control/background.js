// fetch with no eval nearby -- should stay plain cleartext finding, not RCE
fetch('http://example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));

function unrelatedLogic() {
  const x = 1 + 1;
  return x;
}

function faraway() {
  // eval far from any fetch -- should NOT trigger NET-RCE-FETCH-EVAL
  // (still flags as plain DYN-EVAL though)
  const codeStr = "1+1";
  eval(codeStr);
}
