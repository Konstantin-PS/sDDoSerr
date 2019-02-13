/* 
 * sDDoSerr - the programm for simulate shrew (D)DoS attack.
 * 
 * Основной модуль программы.
 * 
 * v.1.1.4.4a от 12.02.19.
 * !Не забывать изменять *argp_program_version под новую версию в парсере!
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
#include <stdlib.h>
#include <time.h>
#include "cmd_parser.h"
#include "udp_sender.h"

int main (int argc, char *argv[])
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
    
    int max_size = settings.max_size; //Брать из массива с прегенерёнными значениями.
    ///Или генерировать полные поля структуры. Но это может занимать слишком много памяти.
    
    
    //Структура сообщения.
    struct Message message_struct;
    
    //Массив из рандомных -дельт от максимальной длины сообщения.
    int message_deltas[settings.num_deltas];
    //printf("Sizeof message_deltas: %i \n", sizeof(message_deltas));
    
    //Инициализация генератора псевдорандомных чисел 
    //(тут seed - текущее время).
    
    //time_t t;
    //srand((unsigned) time(&t));
    
    //srand(time(0));
    srandom(time(0));
    
    printf("\n"); //! Отладка. Убрать.
    //Заполнение массива -дельт псевдорандомными числами.
    for (int j = 0; j <= settings.num_deltas; j++)
        {
            //message_deltas[j] = rand() % max_size-1; //От 0 до % максимум-1.
            message_deltas[j] = random() % max_size-1; //От 0 до % максимум-1.
       //Т.е. при задании .. % 50 будут генерироваться числа от 0 до 49.
       
            //!Дебажный вывод содержимого массива. УБРАТЬ!
            printf("Message_deltas [%i]: %d \n", j, message_deltas[j]);
            //printf("Message_deltas0 [%i]: %d \n", j, random() % max_size-1);
        }
    printf("\n"); //! Отладка. Убрать.
    
    
    //!Переделать сообщение под рандомный мусор внутри (или оставить нули). 
    //!А потом считывать от [0] элемента до [max_size-message_deltas[i]].
    
    
    printf("Выделение памяти под сообщение. \n");
    char message0 [max_size];
    //char *message [max_size];
    //char *message;
    
    printf("Создание сообщения. \n");
    //Создание сообщения.
    //char *message0 = NULL;
    //for (int i = 0; i <= size; i++)
    for (int i = 0; i < max_size; i++)
        {
            message0[i] = '0';
        }
        message0[max_size] = '\0'; //Терминация последнего байта сообщения.
    
    int mes_size = sizeof (message0);
    
    //printf("Message0 from main: %s \n", message0);
    
    //Заполняем структуру сообщения.
    message_struct.message = message0;
    message_struct.mes_size = mes_size;
    
    //Отладка.
    printf("Message from struct: %s \n", message_struct.message);
    printf("Size of message from struct: %i \n", message_struct.mes_size);
    
    
    
    //Забиваем нулями сообщение.
    //memset(&message, 0, max_size);
    
    //Или сразу инициализируем пустое сообщение (с нулями).
    //char message[max_size] = ""; //А вот фиг там! Компилятору не нравится инициализировать объект, зависящий от переменной.
    //Надо динамически выделять память.
    
    //Запись в структуру параметров сообщения.
    //message_params.size = settings.size; //Заменить потом на sizeof(message);
    
    
    printf("Вызов функции отправки. \n");
    
    /* Вызываем функцию отправки. 
     * Потом в цикле с сообщениями, обрезанными по -дельтам 
     * от одного максимального сообщения. 
     */
    //int udp_send = udp_sender (udp_socket, *message);
    //int udp_send = udp_sender (udp_socket, message);
    int udp_send = udp_sender (udp_socket, message_struct);
    
    printf("Закрытие сокета. \n");
    
    //Закрытие сокета.
    int udp_close = udp_closer (udp_socket);


    //Отладка.
    printf("*DEBUG* \n" \
            "url = %s, port = %s, max_size = %i, buffsize = %i, "\
            "protocol = %s, procnum = %i \n" \
            "*DEBUG* \n",\
            settings.url, settings.port, settings.max_size,\
            settings.buffsize, settings.protocol, settings.procnum);
    
    return 0;
}
