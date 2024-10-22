// Функция для генерации случайного цвета
function getRandomColor() {
  const letters = '0123456789ABCDEF';
  let color = '#';
  for (let i = 0; i < 6; i++) {
    color += letters[Math.floor(Math.random() * 16)];
  }
  return color;
}

// Функция для установки случайного фона
function setRandomBackgroundColor() {
  const randomColor = getRandomColor();
  document.body.style.backgroundColor = randomColor;
}

// Функция для выполнения арифметических операций
function calculate(operation) {
  const num1 = parseFloat(document.getElementById('input1').value);
  const num2 = parseFloat(document.getElementById('input2').value);
  let result;

  switch (operation) {
    case 'plus':
      result = num1 + num2;
      break;
    case 'minus':
      result = num1 - num2;
      break;
    case 'multiply':
      result = num1 * num2;
      break;
    case 'divide':
      result = num2 !== 0 ? num1 / num2 : 'Ошибка деления на ноль';
      break;
    case 'power':
      result = Math.pow(num1, num2);
      break;
    case 'sqrt':
      result = Math.sqrt(num1);
      break;
    default:
      result = 'Неизвестная операция';
  }

  displayResult(result);
}

// Функция для вывода результата
function displayResult(result) {
  const resultElement = document.getElementById('result');
  resultElement.innerText = result;

  // Если результат четный — запускаем анимацию салюта
  if (typeof result === 'number' && result % 2 === 0) {
    triggerFireworks();
  }
}

// Функция для случайного числа из заданного диапазона
function generateRandomNumber() {
  const min = parseFloat(document.getElementById('min-value').value);
  const max = parseFloat(document.getElementById('max-value').value);
  
  if (isNaN(min) || isNaN(max)) {
    displayResult('Введите корректные значения');
    return;
  }

  const randomNum = Math.floor(Math.random() * (max - min + 1)) + min;
  displayResult(randomNum);
}

// Функция для анимации салюта (простой пример)
function triggerFireworks() {
  alert('🎆 Салют! Четный результат!');
}

// Привязка кнопок к событиям
document.getElementById('plus').addEventListener('click', function() {
  calculate('plus');
});

document.getElementById('minus').addEventListener('click', function() {
  calculate('minus');
});

document.getElementById('multiply').addEventListener('click', function() {
  calculate('multiply');
});

document.getElementById('divide').addEventListener('click', function() {
  calculate('divide');
});

document.getElementById('power').addEventListener('click', function() {
  calculate('power');
});

document.getElementById('sqrt').addEventListener('click', function() {
  calculate('sqrt');
});

document.getElementById('randomNumber').addEventListener('click', function() {
  generateRandomNumber();
});

// Устанавливаем случайный фон при загрузке страницы
window.onload = function() {
  setRandomBackgroundColor();
};
