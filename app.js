// Получение элементов
const input1 = document.getElementById('input1');
const input2 = document.getElementById('input2');
const resultDisplay = document.getElementById('result');

// Обработчики событий для кнопок операций
document.getElementById('plus').addEventListener('click', () => calculate('+'));
document.getElementById('minus').addEventListener('click', () => calculate('-'));
document.getElementById('multiply').addEventListener('click', () => calculate('*'));
document.getElementById('divide').addEventListener('click', () => calculate('/'));
document.getElementById('power').addEventListener('click', () => calculate('^'));
document.getElementById('sqrt').addEventListener('click', () => calculate('√'));

// Функция для выполнения вычислений
function calculate(operation) {
  const num1 = parseFloat(input1.value); // Преобразование значений полей ввода в числа
  const num2 = parseFloat(input2.value);

  if (isNaN(num1) && operation !== '√') {
    resultDisplay.innerText = 'Введите 1 число!';
    return;
  }

  let result = 0;

  // Выполнение операций в зависимости от нажатой кнопки
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
    case '^':
      if (isNaN(num2)) {
        resultDisplay.innerText = 'Введите степень!';
        return;
      }
      result = Math.pow(num1, num2); // Возведение в степень
      break;
    case '√':
      if (num1 < 0) {
        resultDisplay.innerText = 'Ошибка: Корень из отрицательного числа!';
        return;
      }
      result = Math.sqrt(num1); // Извлечение квадратного корня
      break;
    default:
      break;
  }

  // Отображение результата
  resultDisplay.innerText = result;
}

// Обработчик для кнопки "Вычислить"
document.getElementById('submit').addEventListener('click', () => {
  const num1 = parseFloat(input1.value);
  const num2 = parseFloat(input2.value);
  if (!isNaN(num1) && !isNaN(num2)) {
    resultDisplay.innerText = num1 + num2; // по умолчанию выводится сумма
  } else {
    resultDisplay.innerText = 'Введите оба числа!';
  }
});
