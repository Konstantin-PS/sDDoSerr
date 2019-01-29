/* 
 * sDDoSerr - the programm for simulate shrew (D)DoS attack.
 * 
 * Модуль отправки UDP пакетов.
 * 
 * v.1.0.2a от 29.01.19.
 */
 
/**
    This file is part of sDDoSerr.
sDDoSerr is a research program for emulating shrew (D)DoS traffic and
its analysis (in development).
Use this program on your own pril and risk, as with improper use 
there is a risk of disruption of the network infrastucture.
DDoSerr Copyright © 2019 Konstantin Pankov 
(e-mail: konstantin.p.96@gmail.com), Mikhail Riapolov.

    sDDoSerr is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Any distribution and / or change must be agreed with the authors and
    is prohibited without their permission.
    At this stage of the program development, authors are forbidden to 
    embed any of DDoSerr modules (code components) into other programs.

    sDDoSerr is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with sDDoSerr.  If not, see <https://www.gnu.org/licenses/>.


    Этот файл — часть sDDoSerr.
sDDoSerr — это исследовательская программа для эмуляции "shrew" (D)DoS 
трафика и его анализа (в разработке). 
Используйте эту программу на свой страх и риск, так как при неправильном
применении есть риск нарушения работы сетевой инфраструктуры.
sDDoSerr Copyright © 2019 Константин Панков 
(e-mail: konstantin.p.96@gmail.com), Михаил Ряполов.

   sDDoSerr - свободная программа: вы можете перераспространять ее и/или
   изменять ее на условиях Стандартной общественной лицензии GNU
   в том виде, в каком она была опубликована 
   Фондом свободного программного обеспечения; либо версии 3 лицензии, 
   либо (по вашему выбору) любой более поздней версии.

   Любое распространиение и/или изменение должно быть согласовано с
   авторами и запрещается без их разрешения.
   На данном этапе развития программы авторами запрещается встраивать 
   любой из модулей (компонентов кода) DDoSerr в другие программы.

   sDDoSerr распространяется в надежде, что она будет полезной,
   но БЕЗО ВСЯКИХ ГАРАНТИЙ; даже без неявной гарантии ТОВАРНОГО ВИДА
   или ПРИГОДНОСТИ ДЛЯ ОПРЕДЕЛЕННЫХ ЦЕЛЕЙ. Подробнее см. в Стандартной
   общественной лицензии GNU.

   Вы должны были получить копию Стандартной общественной лицензии GNU
   вместе с этой программой. Если это не так, см.
   <https://www.gnu.org/licenses/>. 
 **/  

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "cmd_parser.h" //Для структуры настроек.
#include "udp_sender.h"

//#define BUF_SIZE 500 //В хэдере. 
//Но надо переделать под получение из settings. 
//Не нужно, если без получения.

//Декларация структуры сокета.
struct Socket udp_socket;

//Переменная под сообщение.
//char *message;

//!Надо делать в классе. А в C нет классов, кажись.

//Функция отправки пакетов.
struct Socket udp_socket_open (struct Settings settings)
{
    //Получаем параметры работы из структуры settings от парсера.
    //int  BUF_SIZE = settings.buffsize; //Размер буффера отправки.
    char *url = settings.url;
    char *port = settings.port;
    int  size = settings.size;
    int  protocol = settings.protocol;
    
    //char buf[BUF_SIZE]; //Буффер. А он не нужен, если не считывать ответ.
    
    int status; //Временная переменная статуса для вызова getaddrinfo().
    
    //Структура параметров сокета типа addrinfo по имени hints.
    struct addrinfo hints;
    struct addrinfo *host_info, *ht; //Информация о хосте и 
                                    //временная переменная для этого.
    
    int sock; //Сокет.
    //int i; //Маркер итераций.
    
    
    //! С соединённым сокетом.
    
    //Получаем адрес(ы), подходящие под адрес хоста и порт.
    //Забиваем нулями все поля структуры hints.
    memset(&hints, 0, sizeof(struct addrinfo));
    
    //Заполняем структуру "подсказок" - параметров создания сокета.
    hints.ai_family = AF_UNSPEC;    // Разрешает IPv4 or IPv6.
    hints.ai_socktype = SOCK_DGRAM; // Сокет датаграмм для UDP.
    hints.ai_flags = AI_NUMERICSERV;
    hints.ai_protocol = protocol;   // Протокол. 0 - любой.
    //hints.ai_protocol = *protocol;   // Протокол. 0 - любой.
        //!Проверить, будет ли работать при такой передаче значения.
    
    
    //Получаем информацию о хосте по подсказкам и записываем в host_info.
    if (status = getaddrinfo(url, port, &hints, &host_info) != 0)
    //Вывод ошибок.
        {
            fprintf(stderr, "getaddrinfo: %s \n", gai_strerror(status));
            exit(EXIT_FAILURE);
        }
    
    //! Далее только для режима с соединением.
    
    /*
     * Функция getaddrinfo() возвращает список адресных структур.
     * Будем пробовать подключиться к каждому адресу пока не получится.
     * Если создание сокета socket() (или подключение connect()) будет
     * неудачным, мы (закроем сокет и) попробуем следующий адрес.
     */ 
    /** Возможно, надо будет убрать проверку на подключение и сразу 
        отсылать UDP пакет без connect. **/
    
    for (ht = host_info; ht != NULL; ht = ht->ai_next)
        {
            sock = socket(ht->ai_family, ht->ai_socktype,\
                     ht->ai_protocol);
            if (sock == -1)
            continue;
            
            if (connect(sock, ht->ai_addr, ht->ai_addrlen) != -1)
            break;                  // Успех

            close(sock); //Закрытие сокета, если не получилось.
        }
    
    // Адрес не найден.
    if (ht == NULL) 
        {
            fprintf(stderr, "Невозможно соединиться с хостом! \n");
            exit(EXIT_FAILURE);
        }
    
    
    //Заполняем структуру сокета.
    udp_socket.sock = sock;
    udp_socket.size = size;
    //udp_socket.address = hints.ai_addr; //Тут 0, хотя в примере значение.
    //udp_socket.address = host_info -> ai_addr;
    
    udp_socket.address = *host_info -> ai_addr;
    //udp_socket.address = *hints.ai_addr; //Отдаёт как есть.
    
    printf("udp_socket.address: %ld \n", udp_socket.address);
    
    //Освобождаем память.
    freeaddrinfo(host_info);
    //freeaddrinfo(ht); //Не надо чистить, т.к. это указатель на уже очищенную память.
    
    return udp_socket; //!Тут, возможно, теряется структура.
    //Нужна структура с полями sock, size, hints.ai_addr;
 }
 
 int udp_sender (struct Socket udp_socket, char message)
{
    int sock = udp_socket.sock;
    int size = udp_socket.size;
    struct sockaddr address = udp_socket.address;
    
    //char *message;     //Переменная под сообщение.
    
    //Отправка пакетов (датаграмм).
    //Забиваем переменную сообщения message заданным в size количеством
    //каких-нибудь символов, например, нулями.
    int stat = 0;
    
    printf("Message from udp_sender: %c \n", message);
    
    if (stat = sendto(sock, &message, size+1, 0, \
        //(struct sockaddr *)&host, sizeof(host)) != size)
        (struct sockaddr *)&address, sizeof(address)) != size+1)
        {
            fprintf(stderr, "Ошибка / частичная запись в сокет. Записано: %i \n", stat);
            exit(EXIT_FAILURE);
        }
    
    //! С соединением до сюда.
    
return 0;
    
}

int udp_closer (struct Socket udp_socket)
{
    int sock = udp_socket.sock;
    close (sock);
    return 0;
}
