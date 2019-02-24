/* 
 * sDDoSerr - the programm for simulate shrew (D)DoS attack.
 * 
 * Основной модуль программы.
 * 
 * v.1.1.5.10a от 24.02.19.
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
    //!Типа лога.
    FILE *log;
    log = fopen ("log.txt", "w+"); //Открытие файла. Поток log.
    
    //Запуск функции сдвоенного парсера и получение на выходе
    //структуры со всеми настройками программы.
    //!printf("Запуск функции парсера. \n");
    struct Settings settings = parser (argc, argv);
    if (settings.debug == 1) //Если установлен флаг дебага.
        {printf("Запуск функции парсера выполнен. \n");}
    
    if (settings.debug == 1)
        {printf("Запуск функции создания сокета. \n");}
    //Вызов функции отправщика пакетов с передачей ему структуры настроек.
    struct Socket udp_sock = udp_socket_open (settings);
    //int udp_sender = udp_sender(settings);
    //! НЕ РАБОТАЕТ с одинаковыми именами!
    
    //!int max_size = settings.max_size; 
    //Брать из массива с прегенерёнными значениями.
    //Или генерировать полные поля структуры. 
    //Но это может занимать слишком много памяти.
    
    
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
    
    if (settings.debug == 1)
        {printf("Отладка. \n");} //! Отладка.
    //Заполнение массива -дельт псевдорандомными числами.
    for (int j = 0; j <= settings.num_deltas; j++)
        {
            //message_deltas[j] = rand() % (settings.max_size-1);
            message_deltas[j] = random() % (settings.max_size-1); 
            //От 0 до % максимум-1.
    //Т.е. при задании .. % 50 будут генерироваться числа от 0 до 49.
       
            //!Дебажный вывод содержимого массива.
            if (settings.debug == 1)
                {printf("Message_deltas [%i]: %d \n", j, message_deltas[j]);}
            //printf("Message_deltas0 [%i]: %d \n", j, random() % settings.max_size-1);
        }
    if (settings.debug == 1)
        {printf("\n");} //! Отладка.
    
    
    //!А потом считывать от [0] элемента до [max_size-message_deltas[i]].
    
    
    if (settings.debug == 1)
        {printf("Выделение памяти под сообщение. \n");}
    
    //!Выделение динамической памяти под полное сообщение.
    char *message_full = malloc (settings.max_size*sizeof(char));
    
    //!Заполнение полного сообщения псевдорандомными символами.
    ///ASCII_START 32, ASCII_END 126
    for (int i = 0; i < settings.max_size; i++)
    {
        message_full[i] = (char) (random() % (126-32))+32;
        //message_full[i] = '0'; //(или) Забивание нулями.
    }
    //!message_full[max_size] = '\0'; //Терминация.
    
    //Вывод нетерминированного сообщения.
    if (settings.debug == 1)
        {printf("Полное сообщение: %.*s \n", settings.max_size,\
            message_full);}
            
    if (settings.debug == 1)
        {printf("Вход в цикл отправки одной пачки. \n");}
    //printf("settings.pack_size %i \n", settings.pack_size);
    
    
    //!Цикл по settings.pack_size на отправку ОДНОЙ "пачки" пакетов.
    
    //Запись указателя на начало сообщения. 
    message_struct.message = message_full;
    
    //int delta, di = 0; //Временные переменные для цикла.
    int di = 0; //Счётчик итерации для дельт.
    for (int i = 0; i <= settings.pack_size; i++)
    {
        if (settings.debug == 1)
            {
                printf("%i-я итерация цикла. \n", i);
                fprintf(log, "%s %i", "%i-я итерация цикла. \n", i);
            }
        
        /**Считывание значения -дельты из message_deltas,
        //"откусывание" от полного сообщения
        //и запись в поле структуры. Вычисление и запись в поле 
        //структуры размера кропнутого сообщения.
        //Проверять маркер цикла считывания на выход за размер settings.num_deltas.
        **/
        
        if (di > settings.num_deltas)
            {
                di = 0; //Если дельт больше, чем пакетов в пачке, то с начала.
            }
        
        
        //delta = message_deltas[di]; //Временная di-ая дельта.
        
        //Размер кропнутого сообщения.
        //message_struct.mes_size = max_size - delta;
        message_struct.mes_size = settings.max_size - message_deltas[di];
        
        //В конце считывания дельт инкремент счётчика.
        di++;
        
        if (settings.debug == 1)
            {printf("Запись кропнутого сообщения в поле структуры \n");}
        //Запись кропнутого сообщения в поле структуры, а точнее,
        //указателя на начало полного сообщения и кропнутый размер.
        
        //! Указатель можно отравлять только один раз, т.к. он не изменяется.
        //! message_struct.message = message_full;
        
        /**
         * Терминация сообщения. 
         * Этот нулевой байт надо очищать перед отправкой след. сообщения!
         
        message_struct.message[message_struct.mes_size] = '\0';
         **/
        
        //Отладка.
        if (settings.debug == 1)
            {
                printf("Message from struct: %.*s \n",\
                message_struct.message);
                printf("Size of message from struct: %i \n",\
                message_struct.mes_size);
            }
        //!Вызов ф-ции отправки.
        if (settings.debug == 1)
            {printf("Вызов функции отправки. \n");}
    
        /* Вызываем функцию отправки. 
         * Потом в цикле с сообщениями, обрезанными по -дельтам 
         * от одного максимального сообщения. 
         */
        //int udp_send = udp_sender (udp_socket, *message);
        //int udp_send = udp_sender (udp_socket, message);
        
        ///int udp_send = udp_sender (udp_socket, message_struct);
        int udp_send;
        if (udp_send = udp_sender (udp_socket, message_struct) != 0)
            {               
                //Если при отправке сообщения что-то пошло не так.
                printf("Ууупс. При отправке пакета что-то пошло не так. \n");
                
                //Очистка динамической памяти под полное сообщение.
                free(message_full);
                
                //Закрытие сокета.
                int udp_close = udp_closer (udp_socket);
                
                //Закрытие файла лога.
                fclose(log);
                
                exit(EXIT_FAILURE);
            }
        
        
        //!Зануление полей структуры.
        
        //! Очистка поля сообщения для удаления теминации.
        //Не требуется, при выводе без терминации.
        //message_struct.message[message_struct.mes_size] = '0';
        
        
    }
    //Конец цикла на отправку одной "пачки" пакетов.
    
    
    if (settings.debug == 1)
        {printf("Закрытие сокета. \n");}
    
    //Закрытие сокета.
    int udp_close = udp_closer (udp_socket);

    //!Очистка динамической памяти под полное сообщение.
    free(message_full);

    //Отладка.
    if (settings.debug == 1)
        {
            printf("*DEBUG* \n" \
            "url = %s, port = %s, max_size = %i, buffsize = %i, "\
            "protocol = %s, procnum = %i \n" \
            "*DEBUG* \n",\
            settings.url, settings.port, settings.max_size,\
            settings.buffsize, settings.protocol, settings.procnum);
        }
    
    //Закрытие файла лога.
    fclose(log);
    
    return 0;
}
