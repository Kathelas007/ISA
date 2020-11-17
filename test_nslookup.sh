# nslookup -type=AAAA -port=1234  .fit.vut.cz localhost

declare -a tests_ns=(
"nslookup -type=A -port=1234 fit.vut.cz localhost"
"nslookup -type=AAAA -port=1234 fit.vut.cz localhost"
"nslookup -type=A -port=1234 add.facebook.com localhost"
"nslookup -type=A -port=1234 dsfsdfuhsdfhsdf755sdfsdf localhost"

)

declare -a results_ns=("147.229.9.26" "NOTIMP" "REFUSED" "NXDOMAIN")

# start server
killall -15 dns &> /dev/null;
./dns -s 8.8.8.8 -f ./test_filter.fil  -p 1234 > /dev/null &
sleep 1;

test_count=0;
test_ok=0;
test_failed=0;

echo -e "org\nfacebook.com\n12345.domainname.google.net\n" > ./test_filter.fil;

echo -e "\n\nnslookup Test\n\n";

# nslookup test
END=${#tests_ns[@]};
for (( i=0; i<$END; i++ ));do
  test_count=$((test_count+1))

  test=${tests_ns[$i]};
  result=`$test | tail -2 | head -1 | awk '{ print $NF }'`;

  if [ "$result" = "${results_ns[$i]}" ]; then
      echo "Test $test_count: OK";
      test_ok=$((test_ok+1))
    else
      echo "Test $test_count: FAILED";
      test_failed=$((test_failed+1))
  fi
done

killall -15 dns &> /dev/null;

echo "";
echo -e "Summary:\t$test_ok/$test_count succeeded";
echo "";

