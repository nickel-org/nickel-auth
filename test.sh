OPEN_PAGE=$(curl -s 'http://localhost:6767/')
if [ "$OPEN_PAGE" != "Public route" ]
then
	echo "Root could not be reached!"
	echo $OPEN_PAGE
	exit -1
fi

OPEN_SECRET_PAGE=$(curl -s 'http://localhost:6767/very/secret')
if [ "$OPEN_SECRET_PAGE" != "Access denied!" ]
then
	echo "Secret page was reached without signing in!"
	echo $OPEN_SECRET_PAGE
	exit -1
fi

LOGIN=$(curl -s -c /tmp/cookie 'http://localhost:6767/login' -H \
	'Content-Type: application/json;charset=UTF-8' \
	--data-binary $'{ "name": "foo","password": "bar" }')
if [ "$LOGIN" != "Successfully logged in." ]
then
	echo "Could not log in!"
	echo $LOGIN
	exit -1
fi

OPEN_SECRET_PAGE_WITH_COOKIE=$(curl -s -b /tmp/cookie "http://localhost:6767/very/secret")
if [ "$OPEN_SECRET_PAGE_WITH_COOKIE" != "Some hidden information!" ]
then
	echo "Secret page could not be reached with cookie!"
	echo $OPEN_SECRET_PAGE_WITH_COOKIE
	exit -1
fi

sleep 10


OPEN_SECRET_PAGE_WITH_COOKIE=$(curl -s -b /tmp/cookie "http://localhost:6767/very/secret")
if [ "$OPEN_SECRET_PAGE_WITH_COOKIE" != "Access denied!" ]
then
	echo "Secret page could be reached after cookie expired!"
	echo $OPEN_SECRET_PAGE_WITH_COOKIE
	exit -1
fi

echo "All tests passing!"
