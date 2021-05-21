/**
  * sDDoSerr - the research programm for simulate shrew (D)DoS attack.
  * 
  * Модуль отправки UDP пакетов.
  * 
  * v.1.0.6.16a от 21.05.21.
  **/
 
/**
    This file is part of sDDoSerr.
sDDoSerr is a research program for emulating shrew (D)DoS traffic 
(in development).
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
    embed any of sDDoSerr modules (code components) into other programs.

    sDDoSerr is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with sDDoSerr.  If not, see <https://www.gnu.org/licenses/>.


    Этот файл — часть sDDoSerr.
sDDoSerr — это исследовательская программа для эмуляции "shrew" (D)DoS 
трафика (в разработке). 
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
   любой из модулей (компонентов кода) sDDoSerr в другие программы.

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

//#include <inttypes.h> //Для вывода таких типов данных как unit32_t
#include <arpa/inet.h> //Для inet_ntop

/* Декларация структуры сокета. */
struct Socket udp_socket;


/* Функция создания и открытия сокета. */
struct Socket udp_socket_open (struct Settings *settings)
{
    /* Получаем параметры работы из структуры settings от парсера. */
    
    /* Временная переменная статуса
     * для отслеживания статуса выполнения getaddrinfo(). */
    int status; 
    
    
    /* Структура параметров сокета типа addrinfo по имени hints. */
    struct addrinfo hints;
    struct addrinfo *host_info, *ht; //Указатель на информацию о хосте и 
                                    //временный указатель для этого.
    
    /* Сокет. */
    int sock;
    
    
    //! С соединённым сокетом.
    
    /* Получаем адрес(ы), подходящие под адрес хоста и порт. */
    /* Забиваем нулями все поля структуры hints. */
    memset(&hints, 0, sizeof(struct addrinfo));
    
    /* Заполняем структуру "подсказок" - параметров создания сокета. */
    hints.ai_family = AF_UNSPEC;    // Разрешает IPv4 or IPv6.
    hints.ai_socktype = SOCK_DGRAM; // Сокет датаграмм для UDP.
    hints.ai_flags = AI_NUMERICSERV;
    hints.ai_protocol = settings->protocol;   // Протокол. 0 - любой.
    
    
    /* Получаем информацию о хосте по подсказкам 
     * и записываем в host_info. */
    if (status = getaddrinfo(settings->host, settings->port,\
    &hints, &host_info) != 0)
    //Вывод ошибок.
        {
            printf("Host: %s \n", settings->host);
            fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
            
            /*
             * Выход при ошибке не нужен,
             * т.к. цель атаки - создание ошибок.
            exit(EXIT_FAILURE);
            */ 
        }
    
    //! Далее для режима с соединением (соединённый сокет).
    
    /*
     * Функция getaddrinfo() возвращает список адресных структур.
     * Будем пробовать подключиться к каждому адресу пока не получится.
     * Если создание сокета socket() (или подключение connect()) будет
     * неудачным, мы (закроем сокет и) попробуем следующий адрес.
     */ 
    /** Возможно, надо будет убрать проверку на подключение и сразу 
        отсылать UDP пакет без connect. **/
    
    //Функция получения целочисленного адреса сокета\
      для дальнейшего преобразования в читаемый адрес.
    //https://stackoverflow.com/questions/1824279/how-to-get-ip-address-from-sockaddr
    // get sockaddr, IPv4 or IPv6:
    void *get_in_addr(struct sockaddr *sa)
    {
        if (sa->sa_family == AF_INET)
            return &(((struct sockaddr_in*)sa)->sin_addr);
        return &(((struct sockaddr_in6*)sa)->sin6_addr);
    }
    
    for (ht = host_info; ht != NULL; ht = ht->ai_next)
        {
            //Создание сокета.
            sock = socket(ht->ai_family, ht->ai_socktype,\
                     ht->ai_protocol);
            
            /// Отладка
                //printf("ht->ai_addrlen: %d \n", ht->ai_addrlen); 
                //printf("ht->ai_addr->sa_family: AF_%i \n",\
                ht->ai_addr->sa_family);
                //printf("ht->ai_family: AF_%i \n", ht->ai_family);
            ///
            
            //Перевод целочисленного адреса сокета в человекочитаемый.
            char s[INET6_ADDRSTRLEN];
            inet_ntop(ht->ai_family,\
             get_in_addr((struct sockaddr *)ht->ai_addr), s, sizeof s);
            printf("Обнаружен адрес: %s \n", s);
            
            
            if (sock == -1)
                {
                    close(sock); //Закрытие сокета, \
                    если не получилось создать.
                    printf("Ошибка создания сокета. Сокет закрыт. \n");
                }
                
                //continue; //НЕТ 1 от sendto() при использовании этого оператора именно здесь!
                //Т.е. тупо пропускается кусок с коннектом.
                //Или если выкинуть кусок с выходом из цикла при успешном соединении.
                //1 итерация для IP. 2 итерации для символьного адреса ya.ru. 10 итераций для google.com.
                //Если раскомментировать кусок кода с коннектом и выходом, то на google.com - 1 итерация,
                //если инкримент счётчика в самом начале.

           /// Кусок с коннектом, без которого всё работает.
           /**
            else
            {
                //Подключение. Не обязательно использовать.
                //Из-за него вылезает ошибка отправки.
                if (connect(sock, ht->ai_addr, ht->ai_addrlen) != -1)
                    {
                        printf("Соединение с хостом выполнено. \n");
                        //Зануление более ненужного указателя\
                         (вместе с полями адреса)\
                         при режиме с соединением, чтобы ошибок не было\
                         (см. коммент около ф-ции sendto()).
                        //Но почему-то всё равно не работает правильно.
                        ht = NULL;
                        break;  //Успешное соединение. \
                        Завершение перебора.
                    }
                else close(sock); //Закрытие сокета, \
                если не получилось подключиться.
            }
            **/
           ///
        }
    
    //Перевод целочисленного адреса сокета в человекочитаемый.
    char s[INET6_ADDRSTRLEN];
    inet_ntop(host_info->ai_family,\
     get_in_addr((struct sockaddr *)host_info->ai_addr), s, sizeof s);
    printf("Использован адрес: %s \n", s);
    //Без коннекта используется в сокете только первый адрес,\
     остальные игнорируются, хоть цикл и проходит через них.\
     Т.е., по сути, выполняется задача куска с коннектом - соединиться\
     с первым рабочим адресом.
    
    
    //Если адрес не найден.
    //if (ht == NULL) 
    if (host_info == NULL) //Т.к. этот указатель не обнуляется,\
     в отличае от указателя ht.
        {
            fprintf(stderr, "Невозможно соединиться с хостом! \n");
        }
    
    
    /* Заполняем структуру сокета. */
    udp_socket.sock = sock;
    //udp_socket.size = size;
    
    udp_socket.address = *host_info -> ai_addr;
    //udp_socket.address = *hints.ai_addr; //Отдаёт как есть.
    
    if (settings->debug == 1)
        {printf("udp_socket.address: %ld \n", udp_socket.address);}
    
    /* Освобождаем память. */
    freeaddrinfo(host_info);
    
    return udp_socket;
 }
 
 
 /* Функция отправки сообщения (пакета, датаграммы). */
 int udp_sender (struct Socket udp_socket,\
 struct Message message_struct)
{    
    /* Отправка пакетов (датаграмм). */
    //int stat = 0;
    ssize_t stat = 0;
    
    if (settings->debug == 1)
    {
        printf("Message from udp_sender: %.*s \n",\
        message_struct.mes_size, message_struct.message);
        printf("Size of the message: %i \n", message_struct.mes_size);
    }
    
    /*
     * If sendto() is used on a connection-mode (SOCK_STREAM, SOCK_SEQPACKET) socket, 
     * the arguments dest_addr and addrlen are ignored (and the error EISCONN may be returned when they are not NULL and 0), 
     * and the error ENOTCONN is returned when the socket was not actually connected. 
     * Otherwise, the address of the target is given by dest_addr with addrlen specifying its size.
     */
    
    if (stat = sendto(udp_socket.sock, message_struct.message,\
        message_struct.mes_size, 0,\
        (struct sockaddr *)&udp_socket.address,\
        sizeof(udp_socket.address)) != message_struct.mes_size)
        {
            fprintf(stderr,\
            "Ошибка / частичная запись в сокет. Записано: %zd из %i \n",\
            stat, message_struct.mes_size);
            return 1;
        }
    
    //! С соединением до сюда.
    
return 0;
    
}

/* Функция закрытия сокета. */
int udp_closer (struct Socket udp_socket)
{
    int sock = udp_socket.sock;
    close (sock);
    return 0;
}
