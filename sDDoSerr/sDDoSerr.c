/* 
 * sDDoSerr - the programm for simulate shrew (D)DoS attack.
 * 
 * Основной модуль программы.
 * 
 * v.1.1.3.1a от 29.01.19.
 * !Не забывать изменять *argp_program_version под новую версию!
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

#include <stdio.h>
#include "cmd_parser.h"
#include "udp_sender.h"

//char *message; //!Надо (глобально) выделить память.

int main (int argc, char *argv[])
//int main ()
{
    //Запуск моей функции сдвоенного парсера и получение на выходе
    //структуры со всеми настройками программы.
    printf("Запуск функции парсера. \n");
    struct Settings settings = parser (argc, argv);
    
    printf("Запуск функции создания сокета. \n");
    //Вызов функции отправщика пакетов с передачей ему структуры настроек.
    struct Socket udp_sock = udp_socket_open (settings);
    //int udp_sender = udp_sender(settings);
    //! НЕ РАБОТАЕТ с одинаковыми именами!
    
    int size = settings.size;
    
    printf("Выделение памяти под сообщение. \n");
    char message [size+1];
    
    printf("Создание сообщения. \n");
    
    //Создание сообщения.
    for (int i = 0; i <= size; i++)
        {
            message[i] = '0';
        }
        message[size] = '\0'; //Терминация последнего байта сообщения.
    
    printf("Вызов функции отправки. \n");
    
    //Вызываем функция отправки. Потом в цикле с сообщениями из 
    //предварительно сгенерированного массива.
    //int udp_send = udp_sender (udp_socket, *message);
    int udp_send = udp_sender (udp_socket, *message);
    
    printf("Закрытие сокета. \n");
    
    //Закрытие сокета.
    int udp_close = udp_closer (udp_socket);


    //Отладка.
    printf("*DEBUG* \n" \
            "url = %s, port = %s, size = %i, buffsize = %i, "\
            "protocol = %s, procnum = %i \n" \
            "*DEBUG* \n",\
            settings.url, settings.port, settings.size,\
            settings.buffsize, settings.protocol, settings.procnum);
    
    return 0;
}
