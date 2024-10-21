// Получение элементов
const input1 = document.getElementById('input1');
const input2 = document.getElementById('input2');
const resultDisplay = document.getElementById('result');

// Обработчики событий для кнопок
document.getElementById('plus').addEventListener('click', () => calculate('+'));
document.getElementById('minus').addEventListener('click', () => calculate('-'));
document.getElementById('multiply').addEventListener('click', () => calculate('*'));
document.getElementById('divide').addEventListener('click', () => calculate('/'));

// Общая функция для выполнения вычислений
function calculate(operation) {
  const num1 = parseFloat(input1.value); // Преобразование значений полей ввода в числа
  const num2 = parseFloat(input2.value);

  let result = 0; // Переменная для хранения результата

  // Выполнение операции в зависимости от нажатой кнопки
  switch (operation) {
    case '+':
      result = num1 + num2;
      break;
    case '-':
      result = num1 - num2;
      break;
    case '*':
      result = num1 * num2;
      break;
    case '/':
      // Проверка деления на ноль
      if (num2 === 0) {
        resultDisplay.innerText = 'Ошибка: Деление на ноль!';
        return;
      } else {
        result = num1 / num2;
      }
      break;
    default:
      break;
  }

  // Отображение результата
  resultDisplay.innerText = result;
}
