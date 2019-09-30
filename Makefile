CXX = g++
TARGET = proxy
FLAGS = -pthread -lssl -lcrypto

$(TARGET) : main.o proxy.o proxy_util.o clienthello_cb.o
	$(CXX) -o $(TARGET) main.o proxy.o proxy_util.o clienthello_cb.o $(FLAGS)

main.o : main.cpp
	$(CXX) -c -o main.o main.cpp

proxy.o : proxy.cpp
	$(CXX) -c -o proxy.o proxy.cpp $(FLAGS)

proxy_util.o : proxy_util.cpp
	$(CXX) -c -o proxy_util.o proxy_util.cpp

clienthello_cb.o : clienthello_cb.cpp
	$(CXX) -c -o clienthello_cb.o clienthello_cb.cpp 

clean : 
	rm *.o proxy



